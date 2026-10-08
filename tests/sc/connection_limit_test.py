#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""The connection limit: this example accepts at most 4 BACnet/SC devices.

Starts the hub itself (with test certificates from tools/make_test_certs.py)
and checks:

  1. The start-up banner says this is an example, accepts at most 4 BACnet/SC
     devices, stops after 24 hours, and names the Chipkin BACnet SC Hub and
     sales@chipkin.com - before the "ready" line.
  2. Four devices are accepted; a fifth gets a BVLC-Result NAK, and the hub
     logs the connection-limit warning naming sales@chipkin.com.
  3. The limit is fixed: --sc-max-hub-connections is refused as an unknown
     option.

    python tests/sc/connection_limit_test.py --exe build/BACnetExampleBSCHUB

Exit code 0 = every check passed.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hub_listener_test as listener  # noqa: E402 - Connect-Request builder and TLS context

RESULTS = []
SALES = "sales@chipkin.com"
PRODUCT = "For a production-ready BACnet/SC hub, the Chipkin BACnet SC Hub: Contact Chipkin sales@chipkin.com"
BANNER = ("This is an example of using the CAS BACnet Stack to build a BACnet/SC hub (B-SCHUB profile). "
          "It is for evaluation and testing only, not for production. It accepts at most 4 BACnet/SC devices "
          "and stops after 24 hours. " + PRODUCT)
LIMIT_MESSAGE = "This example accepts at most 4 BACnet/SC devices; a device was refused. " + PRODUCT


def record(name, ok, detail=""):
    ok = bool(ok)
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.3)
    return False


async def connect_five(uri, cert_dir):
    """Holds 4 accepted devices open and tries a 5th. Returns the 5 BVLC function codes."""
    ctx = listener.make_ssl_context(cert_dir, use_client_cert=True)
    held, replies = [], []
    try:
        for n in range(5):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True, help="path to BACnetExampleBSCHUB")
    args = parser.parse_args()
    exe = Path(args.exe).resolve()
    make_certs = Path(__file__).resolve().parents[2] / "tools" / "make_test_certs.py"

    with tempfile.TemporaryDirectory() as tmp:
        certs = Path(tmp) / "certs"
        subprocess.run([sys.executable, str(make_certs), "--cert-dir", str(certs), "--devices", "1"], check=True,
                       capture_output=True, timeout=60)
        listener.CLIENT_CERT = "client-01"

        # 1 and 2: the start-up banner and the 5th device.
        sc_port = free_port()
        log_path = Path(tmp) / "hub.log"
        with open(log_path, "w") as log:
            hub = subprocess.Popen([str(exe), "--sc-cert-dir", str(certs), "--sc-port", str(sc_port)], stdout=log,
                                   stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, cwd=tmp)
            try:
                record("the hub starts listening", wait_port(sc_port))
                replies = asyncio.run(connect_five(f"wss://127.0.0.1:{sc_port}/", certs))
            except Exception as exc:  # noqa: BLE001 - report, don't crash
                replies = []
                record("five devices connect", False, f"{type(exc).__name__}: {exc}")
            finally:
                hub.terminate()
                try:
                    hub.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    hub.kill()
        output = log_path.read_text(errors="replace")
        banner_at = output.find(BANNER)
        ready_at = output.find(") ready. Vendor ID")
        record("the start-up banner says it is an example, at most 4 devices, 24 hours, and names the product",
               banner_at >= 0 and SALES in BANNER)
        record("the banner comes before the 'ready' line", 0 <= banner_at < ready_at,
               f"banner at {banner_at}, ready at {ready_at}")
        record("sales@chipkin.com appears nowhere else at start-up",
               output[:banner_at].count(SALES) == 0 and
               output[banner_at + len(BANNER):].count(SALES) == output.count(LIMIT_MESSAGE))
        accept, result = listener.FUNC_CONNECT_ACCEPT, 0x00
        record("four devices are accepted", replies[:4] == [accept] * 4, str([hex(r) for r in replies]))
        record("the fifth device is refused (BVLC-Result)", replies[4:] == [result], str([hex(r) for r in replies]))
        record("the hub logs the connection-limit warning naming sales",
               any(LIMIT_MESSAGE in line and "[WARNING]" in line.upper() for line in output.splitlines()) or
               LIMIT_MESSAGE in output)
        record("the warning is logged once (at most once a minute)", output.count(LIMIT_MESSAGE) == 1,
               f"{output.count(LIMIT_MESSAGE)} time(s)")

        # 3. The limit is fixed.
        proc = subprocess.run([str(exe), "--sc-max-hub-connections", "5"], capture_output=True, text=True,
                              timeout=60, stdin=subprocess.DEVNULL, cwd=tmp)
        out = proc.stdout + proc.stderr
        record("--sc-max-hub-connections 5 is refused as an unknown option",
               proc.returncode != 0 and "unknown option" in out, out.strip().splitlines()[-1] if out.strip() else "")

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
