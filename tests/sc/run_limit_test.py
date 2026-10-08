#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""The run limit: this example stops by itself after 24 hours (DEMO_RUN_LIMIT_SECONDS).

Nobody waits 24 hours in a test, so this uses the test-only environment
variable BSCHUB_TEST_RUN_LIMIT_SECONDS, which can only SHORTEN the limit. It
starts the executable itself, in a temporary folder, and checks:

  1. With BSCHUB_TEST_RUN_LIMIT_SECONDS=5 the hub stops by itself after about
     5 seconds, with exit code 0; the start-up banner and the stop message both
     give that run limit, and the stop message names the Chipkin BACnet SC Hub
     and "Contact Chipkin sales@chipkin.com". The start-up says the variable is
     set, for testing only.
  2. The variable can't raise the limit, and nonsense is refused: 0, 86401
     (more than 24 hours) and "abc" make the hub exit with an error at once.
  3. Without the variable the banner says the hub stops after 24 hours.

    python tests/sc/run_limit_test.py --exe build/BACnetExampleBSCHUB

Exit code 0 = every check passed.
"""
import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

RESULTS = []
VARIABLE = "BSCHUB_TEST_RUN_LIMIT_SECONDS"
PRODUCT = "For a production-ready BACnet/SC hub, the Chipkin BACnet SC Hub: Contact Chipkin sales@chipkin.com"
CERTS = Path(__file__).resolve().parents[2] / "certs"


def record(name, ok, detail=""):
    ok = bool(ok)
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_hub(exe, folder, limit=None, timeout=60):
    """Runs the hub (demo certificates) in `folder` until it exits. Returns (exit code, output, seconds)."""
    env = dict(os.environ)
    env.pop(VARIABLE, None)
    if limit is not None:
        env[VARIABLE] = limit
    start = time.time()
    proc = subprocess.run([str(exe), "--sc-cert-dir", str(CERTS), "--sc-port", str(free_port())], env=env,
                          capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, cwd=folder)
    return proc.returncode, proc.stdout + proc.stderr, time.time() - start


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True, help="path to BACnetExampleBSCHUB")
    args = parser.parse_args()
    exe = Path(args.exe).resolve()

    with tempfile.TemporaryDirectory() as tmp:
        # 1. A 5-second run limit.
        rc, out, took = run_hub(exe, tmp, "5")
        record("the hub stops by itself after the run limit, exit code 0", rc == 0 and 4 <= took < 30,
               f"exit {rc} after {took:.1f}s")
        stop = next((line for line in out.splitlines() if "the time is up - stopping" in line), "")
        record("it logs why it stopped, with the run limit", "This example stops after 0m 5s" in stop, stop)
        record("the stop message names the product and the sales contact", PRODUCT in stop, stop)
        record("the start-up banner gives the same run limit", "and stops after 0m 5s. " + PRODUCT in out)
        record("the start-up says the test-only variable is set",
               any(VARIABLE in line and "for testing only" in line for line in out.splitlines()))
        record("the product is named only in the banner and the stop message", out.count("sales@chipkin.com") == 2,
               f"{out.count('sales@chipkin.com')} time(s)")

        # 2. It can only shorten the limit.
        for value in ("0", "86401", "abc"):
            rc, out, took = run_hub(exe, tmp, value, timeout=30)
            record(f"{VARIABLE}={value} is refused at start-up", rc != 0 and VARIABLE in out and took < 20,
                   out.strip().splitlines()[-1] if out.strip() else f"exit {rc}")

        # 3. The real limit: 24 hours (only the banner is checked - stop it at once).
        env = dict(os.environ)
        env.pop(VARIABLE, None)
        log = Path(tmp) / "hub.out"
        with open(log, "w") as f:
            hub = subprocess.Popen([str(exe), "--sc-cert-dir", str(CERTS), "--sc-port", str(free_port())], env=env,
                                   stdout=f, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, cwd=tmp)
            try:
                deadline = time.time() + 20
                while time.time() < deadline and ") ready." not in log.read_text(errors="replace"):
                    time.sleep(0.2)
            finally:
                hub.terminate()
                try:
                    hub.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    hub.kill()
        out = log.read_text(errors="replace")
        record("without the variable the banner says it stops after 24 hours",
               "and stops after 24 hours. " + PRODUCT in out)

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
