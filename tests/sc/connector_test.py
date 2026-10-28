#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""The hub connector: --sc-hub-uri, --sc-failover-uri, --sc-accept-hub-without-hello.

Starts the hub itself (with test certificates from tools/make_test_certs.py)
against a fake hub (fake_hub_server.py, run in this process) and checks:

  1. Primary hub: the hub dials --sc-hub-uri with its own certificate (mutual
     TLS), sends a Connect-Request with the Hello option, and - once the fake
     hub answers with a Connect-Accept - logs the connection. When the fake hub
     closes the connection, the hub logs it and dials again (the stack's own
     reconnect, not the transport's).
  2. Failover: with --sc-hub-uri pointing at nothing, the hub dials
     --sc-failover-uri.
  3. --sc-accept-hub-without-hello: a Connect-Accept without the Hello option
     is not accepted by default, and is with the option.
  4. A revocation list (issuer-crl.pem) that holds no PEM CRL makes the hub
     refuse every hub it would dial (fail closed).
  5. The options are checked: --sc-failover-uri without --sc-hub-uri, a URI
     that isn't wss://, and a missing value are refused.

    python tests/sc/connector_test.py --exe build/BACnetExampleBSCHUB

Exit code 0 = every check passed.
"""
import argparse
import asyncio
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_hub_server as fake  # noqa: E402 - the fake hub's frames and TLS identity
import ip_port_test as ip  # noqa: E402 - start/stop helpers

record = ip.record
RESULTS = ip.RESULTS


class FakeHub:
    """A fake BACnet/SC hub on 127.0.0.1:<port>; records what the hub connector sends it."""

    def __init__(self, certs, send_hello=True, close_after_accept=0.0):
        self.certs = certs
        self.send_hello = send_hello
        self.close_after_accept = close_after_accept
        self.port = ip.free_tcp_port()
        self.requests = []  # (message_id, has_hello) of every Connect-Request
        self.server = None

    def accept_frame(self, message_id):
        frame = fake.build_connect_accept(message_id)
        if self.send_hello:
            return frame
        # The same Connect-Accept without the destination Hello option: clear the
        # destination-options flag and drop the 4-octet option (marker, length, capabilities).
        function, flags, mid = struct.unpack_from(">BBH", frame, 0)
        return struct.pack(">BBH", function, flags & ~0x02, mid) + frame[8:]

    async def handler(self, websocket):
        try:
            async for message in websocket:
                if isinstance(message, str) or len(message) < 4:
                    continue
                function, flags = message[0], message[1]
                message_id = fake.parse_message_id(message)
                if function == fake.FUNC_CONNECT_REQUEST:
                    self.requests.append((message_id, bool(flags & 0x02)))
                    await websocket.send(self.accept_frame(message_id))
                    if self.close_after_accept:
                        await asyncio.sleep(self.close_after_accept)
                        await websocket.close()
                        return
                elif function == fake.FUNC_HEARTBEAT_REQUEST:
                    await websocket.send(fake.build_heartbeat_ack(message_id))
        except websockets.exceptions.ConnectionClosed:
            pass

    async def __aenter__(self):
        self.server = await websockets.serve(self.handler, "127.0.0.1", self.port,
                                             ssl=fake.make_server_ssl_context(self.certs),
                                             subprotocols=[fake.SUBPROTOCOL])
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()


async def wait_until(condition, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return True
        await asyncio.sleep(0.3)
    return condition()


def text_of(path):
    return path.read_text(errors="replace") if path.exists() else ""


async def scenario(exe, certs, tmp, name, hub_args, hub, wait_for, seconds):
    """Runs the hub with `hub_args` until `wait_for(log_text)` or `seconds`; returns the log text."""
    log_path = tmp / f"{name}.log"
    process, log = ip.start_hub(exe, certs, log_path, "--sc-port", str(ip.free_tcp_port()), *hub_args)
    try:
        await wait_until(lambda: wait_for(text_of(log_path)), seconds)
    finally:
        ip.stop_hub(process, log)
    return text_of(log_path)


async def main_async(exe, tmp):
    make_certs = Path(__file__).resolve().parents[2] / "tools" / "make_test_certs.py"
    certs = tmp / "certs"
    subprocess.run([sys.executable, str(make_certs), "--cert-dir", str(certs), "--devices", "1"], check=True,
                   capture_output=True, timeout=60)

    # 1. The primary hub, and the stack's own reconnect after the fake hub closes the connection.
    async with FakeHub(certs, close_after_accept=2.0) as hub:
        uri = f"wss://127.0.0.1:{hub.port}/"
        log = await scenario(exe, certs, tmp, "primary", ["--sc-hub-uri", uri], hub,
                             lambda text: len(hub.requests) >= 2, 90)
        record("primary: the hub dials --sc-hub-uri and sends a Connect-Request", len(hub.requests) >= 1,
               f"{len(hub.requests)} Connect-Request(s)")
        record("primary: the Connect-Request carries the Hello option", bool(hub.requests) and hub.requests[0][1])
        record("primary: the hub logs the dial-out and the connection",
               f'dialing out to {uri}' in log and f'SC audit: connected to hub "{uri}"' in log)
        record("primary: the hub reaches the connected state (state machine 2: 2 -> 3)",
               f"state machine 2: 2 -> 3 ({uri})" in log)
        record("primary: the hub logs the hub closing the connection", f'hub connection "{uri}"' in log and "closed (closeCode=" in log)
        record("primary: the stack dials again after the close", len(hub.requests) >= 2, f"{len(hub.requests)} Connect-Request(s)")
        record("primary: the fake hub's TLS handshake required (and got) the hub's certificate",
               "TLS handshake REJECTED" not in log)

    # 2. The failover hub, with a primary that nothing listens on.
    async with FakeHub(certs) as hub:
        dead = f"wss://127.0.0.1:{ip.free_tcp_port()}/"
        uri = f"wss://127.0.0.1:{hub.port}/"
        log = await scenario(exe, certs, tmp, "failover", ["--sc-hub-uri", dead, "--sc-failover-uri", uri], hub,
                             lambda text: len(hub.requests) >= 1, 120)
        record("failover: the hub tries the primary hub first", f"dialing out to {dead}" in log)
        record("failover: ... and dials --sc-failover-uri when the primary can't be reached",
               f"dialing out to {uri}" in log and len(hub.requests) >= 1, f"{len(hub.requests)} Connect-Request(s)")
        record("failover: the hub reaches the connected state on the failover hub",
               f"state machine 2: 2 -> 3 ({uri})" in log)

    # 3. A Connect-Accept without Hello.
    async with FakeHub(certs, send_hello=False) as hub:
        uri = f"wss://127.0.0.1:{hub.port}/"
        log = await scenario(exe, certs, tmp, "no-hello-default", ["--sc-hub-uri", uri], hub,
                             lambda text: len(hub.requests) >= 1, 30)
        await asyncio.sleep(3)
        log = text_of(tmp / "no-hello-default.log")
        record("no Hello: by default a Connect-Accept without Hello is not accepted",
               len(hub.requests) >= 1 and f"state machine 2: 2 -> 3 ({uri})" not in log,
               f"{len(hub.requests)} Connect-Request(s)")
    async with FakeHub(certs, send_hello=False) as hub:
        uri = f"wss://127.0.0.1:{hub.port}/"
        log = await scenario(exe, certs, tmp, "no-hello-accepted", ["--sc-hub-uri", uri, "--sc-accept-hub-without-hello"],
                             hub, lambda text: f"state machine 2: 2 -> 3 ({uri})" in text, 30)
        record("no Hello: --sc-accept-hub-without-hello accepts it", f"state machine 2: 2 -> 3 ({uri})" in log)
        record("no Hello: ... and warns about the deviation from AB.2.2",
               "--sc-accept-hub-without-hello" in log and "[WARNING]" in log)

    # 4. An unusable revocation list makes the connector refuse every hub.
    crl_certs = tmp / "crl-certs"
    shutil.copytree(certs, crl_certs)
    (crl_certs / "issuer-crl.pem").write_text("this is not a PEM CRL\n")
    async with FakeHub(certs) as hub:
        uri = f"wss://127.0.0.1:{hub.port}/"
        log = await scenario(exe, crl_certs, tmp, "crl", ["--sc-hub-uri", uri], hub,
                             lambda text: f"dialing out to {uri}" in text, 30)
        await asyncio.sleep(5)
        log = text_of(tmp / "crl.log")
        record("revocation list: the hub dials but never reaches the connected state",
               f"dialing out to {uri}" in log and f"state machine 2: 2 -> 3 ({uri})" not in log)
        record("revocation list: the hub says the file holds no PEM CRL",
               "holds no PEM CRL" in log and "(connector)" in log)

    # 5. The options are checked.
    for option, label in ((["--sc-failover-uri", "wss://h:1/"], "--sc-failover-uri without --sc-hub-uri"),
                          (["--sc-hub-uri", "ws://h:1/"], "a ws:// hub URI"),
                          (["--sc-hub-uri", "http://h:1/"], "an http:// hub URI"),
                          (["--sc-hub-uri", "wss://h:1/", "--sc-failover-uri", "ws://h:2/"], "a ws:// failover URI"),
                          (["--sc-hub-uri"], "--sc-hub-uri with no value"),
                          (["--sc-hub-uri", "wss://h:1/", "--sc-failover-uri"], "--sc-failover-uri with no value")):
        ok, last = ip.refused(exe, certs, tmp, *option)
        record(f"{label} is refused", ok, last)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True, help="path to BACnetExampleBSCHUB")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        asyncio.run(main_async(Path(args.exe).resolve(), Path(tmp)))
    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
