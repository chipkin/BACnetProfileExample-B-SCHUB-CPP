#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""The optional BACnet/IP port: Network Port 1, opened only with --port <n>.

Starts the hub itself (with test certificates from tools/make_test_certs.py)
and checks, over plain BACnet/IP (UDP, hand-built BVLC/NPDU/APDU - no BACnet
library needed):

  1. Without --port the hub opens no BACnet/IP port: it says nothing about
     UDP or Network Port 1 (rpm_test.py checks Object_List over BACnet/SC).
  2. With --port <n>: the hub says it listens on UDP port <n>; Who-Is gets an
     I-Am from Device 389022; Object_List holds Network Port 1 and 2;
     Network Port 1 reports its BACnet_IP_UDP_Port and a 4-octet IP_Address;
     Network_Number is 0 (unknown) until --ip-network-number is given, then the
     number given; both Network Ports carry their names; every property in the
     Device's and the Network Ports' Property_List reads.
  3. The BACnet/SC listener still works next to it: a device is accepted.
  4. --port and --ip-network-number are checked: a missing, zero or non-numeric
     port is refused; --ip-network-number without --port is refused.

    python tests/sc/ip_port_test.py --exe build/BACnetExampleBSCHUB

Exit code 0 = every check passed. Never touches UDP port 47808.
"""
import argparse
import asyncio
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hub_listener_test as listener  # noqa: E402 - Connect-Request builder and TLS context

RESULTS = []
HUB_INSTANCE = 389022
DEVICE_OBJECT_ID = struct.pack(">I", (8 << 22) | HUB_INSTANCE)


def record(name, ok, detail=""):
    ok = bool(ok)
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def free_tcp_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(path, text, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if path.exists() and text in path.read_text(errors="replace"):
            return True
        time.sleep(0.3)
    return False


def start_hub(exe, certs, log_path, *args):
    log = open(log_path, "w")
    process = subprocess.Popen([str(exe), "--sc-cert-dir", str(certs), *args], stdout=log, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, cwd=log_path.parent)
    return process, log


def stop_hub(process, log):
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
    log.close()


def bvlc(npdu_apdu):
    """Original-Unicast-NPDU (BVLC function 0x0A)."""
    return struct.pack(">BBH", 0x81, 0x0A, 4 + len(npdu_apdu)) + npdu_apdu


def exchange(port, request, wait=3.0):
    """Sends one UDP datagram to the hub; returns the first datagram back, or None."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(wait)
        s.sendto(request, ("127.0.0.1", port))
        try:
            return s.recvfrom(2048)[0]
        except (socket.timeout, ConnectionResetError):  # Windows reports an ICMP "port unreachable" this way
            return None


def read_property(port, invoke_id, object_id, property_id):
    """The value bytes of a ReadProperty (between the opening and closing tag 3), or None."""
    size = max(1, (property_id.bit_length() + 7) // 8)  # the property identifier, context tag 1
    prop = bytes([0x18 + size]) + property_id.to_bytes(size, "big")
    apdu = bytes([0x00, 0x05, invoke_id, 0x0C, 0x0C]) + object_id + prop
    reply = exchange(port, bvlc(bytes([0x01, 0x04]) + apdu))
    if reply is None or len(reply) < 8:
        return None
    npdu_start = 4
    apdu_start = npdu_start + 2  # version, control (no network addresses in a local reply)
    if reply[apdu_start] >> 4 != 3 or reply[apdu_start + 1] != invoke_id:  # Complex-ACK for this invoke id
        return None
    body = reply[apdu_start + 3:]
    opening = body.index(b"\x3e")
    return body[opening + 1:body.rindex(b"\x3f")]


def object_ids(value):
    """Every application-tagged ObjectIdentifier (tag 0xC4) in an Object_List value."""
    found, i = [], 0
    while i + 5 <= len(value):
        if value[i] == 0xC4:
            (raw,) = struct.unpack_from(">I", value, i + 1)
            found.append((raw >> 22, raw & 0x3FFFFF))
            i += 5
        else:
            i += 1
    return found


def unsigned(value):
    if not value or value[0] & 0xF8 != 0x20:
        return None
    return int.from_bytes(value[1:1 + (value[0] & 7)], "big")


def network_port_id(instance):
    return struct.pack(">I", (56 << 22) | instance)


def character_string(value):
    """The text of an application-tagged CharacterString value (tag 7), or None."""
    if not value or value[0] >> 4 != 7:
        return None
    length, offset = value[0] & 7, 1
    if length == 5:
        length, offset = value[1], 2
    return value[offset + 1:offset + length].decode("utf-8", "replace")  # skip the encoding octet


def property_list(port, object_id):
    """The property identifiers of an object's Property_List (property 371), or None."""
    value = read_property(port, 20, object_id, 371)
    if value is None:
        return None
    found, i = [], 0
    while i < len(value):
        tag = value[i]
        if tag >> 4 == 9:  # application tag 9: enumerated
            n = tag & 7
            found.append(int.from_bytes(value[i + 1:i + 1 + n], "big"))
            i += 1 + n
        else:
            return None
    return found


async def sc_device_accepted(sc_port, certs):
    ctx = listener.make_ssl_context(certs, use_client_cert=True)
    ws = await websockets.connect(f"wss://127.0.0.1:{sc_port}/", ssl=ctx, subprotocols=[listener.SUBPROTOCOL],
                                  open_timeout=5)
    try:
        await ws.send(listener.build_connect_request(bytes([2, 0, 0, 0, 0, 1]), bytes([1] * 16), message_id=7))
        return listener.parse_bvlc_function(await asyncio.wait_for(ws.recv(), timeout=5)) == listener.FUNC_CONNECT_ACCEPT
    finally:
        ws.transport.close()


def refused(exe, certs, tmp, *args):
    proc = subprocess.run([str(exe), "--sc-cert-dir", str(certs), *args], capture_output=True, text=True, timeout=60,
                          stdin=subprocess.DEVNULL, cwd=tmp)
    out = proc.stdout + proc.stderr
    return proc.returncode != 0, out.strip().splitlines()[-1] if out.strip() else ""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True, help="path to BACnetExampleBSCHUB")
    args = parser.parse_args()
    exe = Path(args.exe).resolve()
    make_certs = Path(__file__).resolve().parents[2] / "tools" / "make_test_certs.py"

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        certs = tmp / "certs"
        subprocess.run([sys.executable, str(make_certs), "--cert-dir", str(certs), "--devices", "1"], check=True,
                       capture_output=True, timeout=60)
        listener.CLIENT_CERT = "client-01"

        # 1. Default: SC only (the Object_List with only Network Port 2 is checked by rpm_test.py over BACnet/SC).
        sc_port = free_tcp_port()
        log_path = tmp / "default.log"
        hub, log = start_hub(exe, certs, log_path, "--sc-port", str(sc_port))
        try:
            record("default: the hub starts", wait_for(log_path, ") ready. Vendor ID"))
        finally:
            stop_hub(hub, log)
        console = log_path.read_text(errors="replace")
        record("default: the hub says nothing about BACnet/IP or a UDP port",
               "BACnet/IP on UDP" not in console and "UDP port" not in console and "Network Port 1" not in console)

        # 2 and 3. --port <n>.
        udp_port = free_udp_port()
        sc_port = free_tcp_port()
        log_path = tmp / "ip.log"
        hub, log = start_hub(exe, certs, log_path, "--port", str(udp_port), "--sc-port", str(sc_port))
        try:
            record("--port: the hub starts", wait_for(log_path, ") ready. Vendor ID"))
            record("--port: the hub says it listens on that UDP port",
                   f"Listening for BACnet/IP on UDP port {udp_port} (Network Port 1)" in log_path.read_text(errors="replace"))
            iam = exchange(udp_port, bvlc(bytes([0x01, 0x00, 0x10, 0x08])))
            record("--port: Who-Is gets an I-Am from Device 389022", iam is not None and (b"\xc4" + DEVICE_OBJECT_ID) in iam,
                   iam.hex() if iam else "no reply")
            object_list = read_property(udp_port, 1, DEVICE_OBJECT_ID, 76)
            ids = object_ids(object_list or b"")
            record("--port: Object_List holds Network Port 1 and Network Port 2",
                   (56, 1) in ids and (56, 2) in ids and (8, HUB_INSTANCE) in ids, str(ids))
            udp_value = unsigned(read_property(udp_port, 2, network_port_id(1), 412) or b"")
            record("--port: Network Port 1 reports BACnet_IP_UDP_Port = the port given", udp_value == udp_port,
                   f"{udp_value} (expected {udp_port})")
            ip_value = read_property(udp_port, 3, network_port_id(1), 400)
            record("--port: Network Port 1 reports a 4-octet IP_Address", ip_value is not None and len(ip_value) == 5 and
                   ip_value[0] == 0x64, ip_value.hex() if ip_value else "no value")
            record("--port: Network Port 1's Object_Name is \"BACnet IP\" (Network Port 2's is \"BACnet SC\")",
                   character_string(read_property(udp_port, 7, network_port_id(1), 77)) == "BACnet IP" and
                   character_string(read_property(udp_port, 8, network_port_id(2), 77)) == "BACnet SC",
                   f"{character_string(read_property(udp_port, 7, network_port_id(1), 77))!r}")
            unreadable = []
            for label, object_id in (("Device", DEVICE_OBJECT_ID), ("Network Port 1", network_port_id(1)),
                                     ("Network Port 2", network_port_id(2))):
                listed = property_list(udp_port, object_id)
                if not listed:
                    unreadable.append(f"{label}: no Property_List")
                    continue
                for number_ in listed:
                    if read_property(udp_port, 21, object_id, number_) is None:
                        unreadable.append(f"{label} property {number_}")
            record("--port: every property in the Device's and both Network Ports' Property_List reads over BACnet/IP",
                   not unreadable, ", ".join(unreadable[:6]))
            number = unsigned(read_property(udp_port, 4, network_port_id(1), 425) or b"")
            record("--port: Network_Number is 0 until --ip-network-number is given", number == 0, str(number))
            record("--port: the BACnet/SC listener still accepts a device", asyncio.run(sc_device_accepted(sc_port, certs)))
        finally:
            stop_hub(hub, log)

        # 2b. --ip-network-number / --sc-network-number.
        udp_port = free_udp_port()
        sc_port = free_tcp_port()
        log_path = tmp / "numbers.log"
        hub, log = start_hub(exe, certs, log_path, "--port", str(udp_port), "--sc-port", str(sc_port),
                             "--ip-network-number", "7", "--sc-network-number", "9")
        try:
            record("network numbers: the hub starts", wait_for(log_path, ") ready. Vendor ID"))
            ip_number = unsigned(read_property(udp_port, 5, network_port_id(1), 425) or b"")
            sc_number = unsigned(read_property(udp_port, 6, network_port_id(2), 425) or b"")
            record("--ip-network-number 7 is Network Port 1's Network_Number", ip_number == 7, str(ip_number))
            record("--sc-network-number 9 is Network Port 2's Network_Number", sc_number == 9, str(sc_number))
        finally:
            stop_hub(hub, log)

        # 4. The options are checked.
        for option, label in ((["--port"], "--port with no value"),
                              (["--port", "0"], "--port 0"),
                              (["--port", "70000"], "--port 70000"),
                              (["--port", "abc"], "--port abc"),
                              (["--ip-network-number", "5"], "--ip-network-number without --port"),
                              (["--port", "47999", "--ip-network-number", "0"], "--ip-network-number 0"),
                              (["--port", "47999", "--ip-network-number", "70000"], "--ip-network-number 70000"),
                              (["--sc-network-number", "x"], "--sc-network-number x"),
                              (["--port", "47999", "--ip-network-number", "5", "--sc-network-number", "5"],
                               "the same network number on both ports")):
            ok, last = refused(exe, certs, tmp, *option)
            record(f"{label} is refused", ok, last)

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
