#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""Start-up: --help, the log file, and no BACnet/IP.

Starts the executable itself, in a temporary folder, on the demo certificates,
and checks:

  1. --help links to the repository on GitHub, says the certificate request
     (hub-cari-request.zip) is created at start-up if it doesn't already exist,
     names logs/B-SCHUB.log, no longer lists --port or --generate-csr, and
     doesn't advertise the product (only the start-up and the limit messages do).
  2. The log file: logs/B-SCHUB.log in the folder the hub runs in (made if
     missing), with everything the console showed - the example's own lines,
     libwebsockets' and the stack's - and its full path printed at start-up.
     A restart empties it first.
  3. No BACnet/IP: while the hub runs, UDP port 47808 is still free, and the
     start-up says nothing about BACnet/IP.

    python tests/sc/startup_test.py --exe build/BACnetExampleBSCHUB

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
REPOSITORY = "https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP"
CERTS = Path(__file__).resolve().parents[2] / "certs"


def record(name, ok, detail=""):
    ok = bool(ok)
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def udp_port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def names_file(line, path):
    """True if the log line quotes a path to `path` (compared as files, so a Windows
    8.3 short name such as RUNNER~1 matches the long one)."""
    quoted = line.split('"')[1::2]
    return any(os.path.exists(q) and os.path.samefile(q, path) for q in quoted)


def normalize(text):
    return text.replace("\r\n", "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True, help="path to BACnetExampleBSCHUB")
    args = parser.parse_args()
    exe = Path(args.exe).resolve()
    env = dict(os.environ, BSCHUB_TEST_RUN_LIMIT_SECONDS="4")  # each run stops by itself (run_limit_test.py)

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # 1. --help
        proc = subprocess.run([str(exe), "--help"], capture_output=True, text=True, timeout=60,
                              stdin=subprocess.DEVNULL, cwd=tmp)
        text = proc.stdout + proc.stderr
        record("--help exits 0", proc.returncode == 0)
        record("--help links to the repository", REPOSITORY in text)
        record("--help says the certificate request is created at start-up if it doesn't exist",
               "hub-cari-request.zip" in text and "Created at start-up if it doesn't already exist" in text)
        record("--help names the log file", "logs/B-SCHUB.log" in text)
        record("--help no longer lists --port or --generate-csr", "--port " not in text and "--generate-csr" not in text)
        record("--help doesn't advertise the product", "sales@chipkin.com" not in text)
        record("--help doesn't make a log file", not (tmp / "logs").exists())

        # 2 and 3. A run: the log file, and no BACnet/IP.
        log_file = tmp / "logs" / "B-SCHUB.log"
        udp_free_before = udp_port_free(47808)
        hub = subprocess.Popen([str(exe), "--sc-cert-dir", str(CERTS), "--sc-port", str(free_port())], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                               cwd=tmp, text=True)
        time.sleep(2)
        udp_free_during = udp_port_free(47808)
        console = hub.communicate(timeout=60)[0]
        if udp_free_before:
            record("no BACnet/IP: UDP port 47808 stays free while the hub runs", udp_free_during)
        else:
            print("[SKIP] UDP port 47808 is in use by another program - can't check the hub leaves it alone")
        record("no BACnet/IP: the start-up says nothing about BACnet/IP or UDP",
               "BACnet/IP on UDP" not in console and "UDP port" not in console)
        record("the hub runs and stops by itself", hub.returncode == 0, f"exit {hub.returncode}")
        record("logs/B-SCHUB.log is made in the folder the hub runs in", log_file.is_file())
        logged = normalize(log_file.read_text(errors="replace")) if log_file.is_file() else ""
        line = next((x for x in console.splitlines() if "log file:" in x), "")
        record("the start-up prints the log file's full path",
               names_file(line, log_file) and Path(line.split('"')[1]).is_absolute(), line)
        record("the log file has everything the console showed", logged == normalize(console),
               f"{len(logged)} vs {len(console)} characters")
        record("... including libwebsockets' lines", "lws:" in logged)
        record("... and the stop message", "the time is up - stopping" in logged)

        # A restart empties the log first.
        with open(log_file, "a") as f:
            f.write("OLD RUN MARKER\n")
        proc = subprocess.run([str(exe), "--sc-cert-dir", str(CERTS), "--sc-port", str(free_port())], env=env,
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL, cwd=tmp)
        logged = normalize(log_file.read_text(errors="replace"))
        record("a restart empties the log file first", "OLD RUN MARKER" not in logged and
               logged.startswith("BACnet B-SCHUB (BACnet/SC Hub) Example"), logged.splitlines()[0] if logged else "")
        record("... and it again has the whole run", logged == normalize(proc.stdout + proc.stderr))

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
