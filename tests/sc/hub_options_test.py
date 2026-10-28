#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""The hub options: --device-name, --sc-max-hub-connections, --sc-rate-limit.

Starts the hub itself (with test certificates from tools/make_test_certs.py)
and checks:

  1. --device-name: the Device's Object_Name is the name given (read over the
     optional BACnet/IP port, --port), the hub's certificate request is made
     for that name, and an empty name, one over 128 bytes, or a missing value is
     refused.
  2. --sc-max-hub-connections only lowers the limit of 4: with 2, two devices are
     accepted, the third gets a BVLC-Result NAK and the warning names 2; 5, 0 and
     abc are refused (5 with the example's "at most 4" message).
  3. --sc-rate-limit and --sc-rate-limit-total: a burst of connection attempts
     past the limit is refused before the TLS handshake and logged; with the
     defaults, or with 0 (off), the same burst is not; bad values are refused.

    python tests/sc/hub_options_test.py --exe build/BACnetExampleBSCHUB

Exit code 0 = every check passed. Never touches UDP port 47808.
"""
import argparse
import asyncio
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import websockets
from cryptography import x509
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hub_listener_test as listener  # noqa: E402 - Connect-Request builder and TLS context
import ip_port_test as ip  # noqa: E402 - start/stop helpers and the raw BACnet/IP reads

RESULTS = ip.RESULTS
record = ip.record


def object_name(udp_port):
    value = ip.read_property(udp_port, 9, ip.DEVICE_OBJECT_ID, 77)
    if not value:
        return None
    length = value[0] & 7
    offset = 1
    if length == 5:
        length = value[1]
        offset = 2
    return value[offset + 1:offset + length].decode("utf-8", "replace")  # skip the encoding octet


async def connect_devices(uri, certs, count):
    """Holds `count` devices open; returns the BVLC function code each got back."""
    ctx = listener.make_ssl_context(certs, use_client_cert=True)
    held, replies = [], []
    try:
        for n in range(count):
            ws = await websockets.connect(uri, ssl=ctx, subprotocols=[listener.SUBPROTOCOL], open_timeout=5)
            held.append(ws)
            await ws.send(listener.build_connect_request(bytes([2, 0, 0, 0, 0, n + 1]), bytes([n + 1] * 16),
                                                         message_id=100 + n))
            replies.append(listener.parse_bvlc_function(await asyncio.wait_for(ws.recv(), timeout=5)))
        await asyncio.sleep(1)  # the hub logs from its main loop
    finally:
        for ws in held:
            ws.transport.close()
    return replies


def burst(port, attempts):
    """Opens `attempts` TCP connections as fast as possible; returns how many were hung up at once."""
    hung_up = 0
    sockets = []
    for _ in range(attempts):
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        sockets.append(s)
    time.sleep(0.5)
    for s in sockets:
        s.settimeout(0.2)
        try:
            if s.recv(1) == b"":  # the hub closed it before any TLS handshake
                hung_up += 1
        except socket.timeout:
            pass
        except OSError:
            hung_up += 1
        finally:
            s.close()
    return hung_up


def run_hub_for_burst(exe, certs, tmp, name, attempts, *options):
    sc_port = ip.free_tcp_port()
    log_path = tmp / f"{name}.log"
    hub, log = ip.start_hub(exe, certs, log_path, "--sc-port", str(sc_port), *options)
    try:
        ok = ip.wait_for(log_path, "BACnet/SC: listening for WebSocket/TLS connections")
        hung_up = burst(sc_port, attempts) if ok else -1
        time.sleep(1)
    finally:
        ip.stop_hub(hub, log)
    return hung_up, log_path.read_text(errors="replace")


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

        # 1. --device-name
        udp_port = ip.free_udp_port()
        log_path = tmp / "name.log"
        hub, log = ip.start_hub(exe, certs, log_path, "--port", str(udp_port), "--sc-port", str(ip.free_tcp_port()),
                                "--device-name", "Hub Seven")
        try:
            record("--device-name: the hub starts", ip.wait_for(log_path, ") ready. Vendor ID"))
            name = object_name(udp_port)
            record("--device-name: Object_Name is the name given", name == "Hub Seven", repr(name))
        finally:
            ip.stop_hub(hub, log)
        record("--device-name: the ready line names it", "Hub Seven" in log_path.read_text(errors="replace"))

        empty_certs = tmp / "emptycerts"
        empty_certs.mkdir()
        log_path = tmp / "name-csr.log"
        hub, log = ip.start_hub(exe, empty_certs, log_path, "--sc-port", str(ip.free_tcp_port()),
                                "--device-name", "Hub Request Name")
        try:
            record("--device-name: a hub with no certificates starts", ip.wait_for(log_path, "certificate request:"))
        finally:
            ip.stop_hub(hub, log)
        csr_files = list(empty_certs.glob("cert1/device-*/port-*/csr-hub.pem"))
        subject = None
        if csr_files:
            csr = x509.load_pem_x509_csr(csr_files[0].read_bytes())
            subject = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        record("--device-name: the certificate request is for that name", subject == "Hub Request Name", repr(subject))

        for value, label in (("", "an empty name"), ("x" * 129, "a 129-byte name")):
            refused, last = ip.refused(exe, certs, tmp, "--device-name", value)
            record(f"--device-name: {label} is refused", refused, last)
        ok, last = ip.refused(exe, certs, tmp, "--device-name")
        record("--device-name with no value is refused", ok, last)

        # 2. --sc-max-hub-connections only lowers the limit.
        sc_port = ip.free_tcp_port()
        log_path = tmp / "limit.log"
        hub, log = ip.start_hub(exe, certs, log_path, "--sc-port", str(sc_port), "--sc-max-hub-connections", "2")
        try:
            record("--sc-max-hub-connections 2: the hub starts", ip.wait_for(log_path, ") ready. Vendor ID"))
            replies = asyncio.run(connect_devices(f"wss://127.0.0.1:{sc_port}/", certs, 3))
        finally:
            ip.stop_hub(hub, log)
        output = log_path.read_text(errors="replace")
        record("--sc-max-hub-connections 2: two devices are accepted, the third is refused",
               replies == [listener.FUNC_CONNECT_ACCEPT] * 2 + [0x00], str([hex(r) for r in replies]))
        record("--sc-max-hub-connections 2: the warning says at most 2",
               "This example accepts at most 2 BACnet/SC devices; a device was refused." in output)

        ok, last = ip.refused(exe, certs, tmp, "--sc-max-hub-connections", "5")
        record("--sc-max-hub-connections 5 is refused: the limit can only be lowered", ok and "at most 4" in last, last)
        for value in ("0", "abc", "-1", "70000"):
            ok, last = ip.refused(exe, certs, tmp, "--sc-max-hub-connections", value)
            record(f"--sc-max-hub-connections {value} is refused", ok, last)
        ok, last = ip.refused(exe, certs, tmp, "--sc-max-hub-connections")
        record("--sc-max-hub-connections with no value is refused", ok, last)

        # 3. Rate limits.
        hung_up, output = run_hub_for_burst(exe, certs, tmp, "rate-per-address", 8, "--sc-rate-limit", "2",
                                            "--sc-rate-limit-total", "0")
        record("--sc-rate-limit 2: a burst of 8 attempts is cut off", hung_up >= 4, f"{hung_up} hung up")
        record("--sc-rate-limit 2: the refusal is logged (per-address limit of 2)",
               "SC rate limit: refusing a new connection from 127.0.0.1" in output and
               "per-address limit of 2 attempt(s)/sec" in output)
        hung_up, output = run_hub_for_burst(exe, certs, tmp, "rate-total", 8, "--sc-rate-limit", "0",
                                            "--sc-rate-limit-total", "3")
        record("--sc-rate-limit-total 3: a burst of 8 attempts is cut off", hung_up >= 3, f"{hung_up} hung up")
        record("--sc-rate-limit-total 3: the refusal is logged (total limit of 3)",
               "total limit of 3 attempt(s)/sec" in output)
        hung_up, output = run_hub_for_burst(exe, certs, tmp, "rate-default", 8)
        record("the default limits (10 per address, 50 in total) let a burst of 8 through",
               hung_up == 0 and "SC rate limit" not in output, f"{hung_up} hung up")
        hung_up, output = run_hub_for_burst(exe, certs, tmp, "rate-off", 40, "--sc-rate-limit", "0",
                                            "--sc-rate-limit-total", "0")
        record("--sc-rate-limit 0 --sc-rate-limit-total 0 turn the limits off",
               hung_up == 0 and "SC rate limit" not in output, f"{hung_up} hung up")
        for option in (["--sc-rate-limit", "-1"], ["--sc-rate-limit", "x"], ["--sc-rate-limit-total", "70000"],
                       ["--sc-rate-limit"], ["--sc-rate-limit-total"]):
            ok, last = ip.refused(exe, certs, tmp, *option)
            record(f"{' '.join(option)} is refused", ok, last)

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
