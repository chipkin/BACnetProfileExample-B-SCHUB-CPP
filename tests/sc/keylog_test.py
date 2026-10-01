#!/usr/bin/env python3
"""
Checks --sc-keylog-file (issue #68): the TLS session secrets the hub writes are
the real ones, in the NSS key log format Wireshark reads. Starts the executable
itself on free ports in a temporary folder; needs no running hub.

    python tests/sc/keylog_test.py --exe build/Release/BACnetExampleBSCHUB.exe

The peer in each check is Python's ssl module with its own keylog_filename,
so both ends of the same session log their secrets; they must match line for
line (same client random, same secrets):

  1. hub function (listener): a device connects with a client certificate;
  2. hub connector (--sc-hub-uri): the hub dials a TLS server run here;
and the HTTPS status page (--http-tls) is NOT logged - the key log is for
BACnet/SC only. Plus: GET /health says "tls_keylog":true (false without the option), and
start-up fails for a key log file that can't be opened.

Exit code 0 = every check passed.
"""
import argparse
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import cert_paths

RESULTS = []
LABELS = ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0",
          "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET")


def record(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def keylog_lines(path):
    """{client_random: {label: secret}} from an NSS key log file."""
    sessions = {}
    if not Path(path).exists():
        return sessions
    for line in Path(path).read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and not line.startswith("#"):
            sessions.setdefault(parts[1].lower(), {})[parts[0]] = parts[2].lower()
    return sessions


def wait_for(predicate, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


def compare(name, hub_log, peer_log):
    peer = keylog_lines(peer_log)
    wait_for(lambda: all(cr in keylog_lines(hub_log) and len(keylog_lines(hub_log)[cr]) == len(LABELS)
                         for cr in peer), 5)
    hub = keylog_lines(hub_log)
    if not peer:
        record(f"{name}: the peer logged a session", False)
        return
    for client_random, secrets in peer.items():
        record(f"{name}: hub logged all 5 TLS 1.3 secrets for the session",
               set(hub.get(client_random, {})) == set(LABELS), sorted(hub.get(client_random, {})))
        record(f"{name}: hub secrets match the peer's", hub.get(client_random) == secrets)


class Hub:
    def __init__(self, exe, cert_dir, tmp, *args):
        self.log = tmp / f"hub-{time.time_ns()}.log"
        self.http_port = free_port()
        self.sc_port = free_port()
        self.proc = subprocess.Popen(
            [str(exe), "--port", str(free_port()), "--sc-port", str(self.sc_port), "--http-port",
             str(self.http_port), "--sc-cert-dir", str(cert_dir), *args],
            stdout=self.log.open("w"), stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

    def output(self):
        return self.log.read_text(errors="replace") if self.log.exists() else ""

    def wait_listening(self):
        return wait_for(lambda: "listening for WebSocket/TLS connections" in self.output())

    def stop(self):
        self.proc.kill()
        self.proc.wait()


def health(port, https=False):
    ctx = ssl._create_unverified_context() if https else None
    scheme = "https" if https else "http"
    with urllib.request.urlopen(f"{scheme}://127.0.0.1:{port}/health", timeout=5, context=ctx) as r:
        return json.loads(r.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True, help="path to BACnetExampleBSCHUB")
    args = parser.parse_args()
    exe = Path(args.exe).resolve()

    # ignore_cleanup_errors: on Windows an ssl.SSLContext keeps its keylog_filename
    # open for as long as it lives, so the folder can't always be removed at once.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        tmp = Path(tmp)
        certs = tmp / "certs"
        subprocess.run([str(exe), "--sc-cert-dir", str(certs), "--generate-certs", "1"], check=True,
                       capture_output=True, timeout=60)
        client_cert, client_key = cert_paths.client_files(certs, "client-01")
        issuer = cert_paths.issuer_certificate(certs)

        # Start-up refuses a key log it can't open.
        proc = subprocess.run([str(exe), "--sc-cert-dir", str(certs), "--sc-keylog-file",
                               str(tmp / "no-such-folder" / "keys.log")], capture_output=True, text=True,
                              timeout=30, stdin=subprocess.DEVNULL)
        record("unopenable --sc-keylog-file fails start-up", proc.returncode != 0,
               (proc.stdout + proc.stderr).strip().splitlines()[-1] if (proc.stdout + proc.stderr).strip() else "")

        # Without the option: no key log, /health says so.
        hub = Hub(exe, certs, tmp)
        try:
            hub.wait_listening()
            record("/health tls_keylog false without the option", health(hub.http_port).get("tls_keylog") is False)
        finally:
            hub.stop()

        # 1: listener, and HTTPS (which must stay out of the key log), one hub.
        hub_log = tmp / "hub-keys.log"
        hub = Hub(exe, certs, tmp, "--sc-keylog-file", str(hub_log), "--http-tls")
        try:
            record("hub starts listening with --sc-keylog-file", hub.wait_listening())
            record("start-up warns that the key log is on", "TLS KEY LOG ON" in hub.output())

            peer_log = tmp / "device-keys.log"
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.check_hostname = False
            ctx.load_verify_locations(issuer)
            ctx.load_cert_chain(client_cert, client_key)
            ctx.keylog_filename = str(peer_log)
            with socket.create_connection(("127.0.0.1", hub.sc_port), timeout=5) as raw:
                with ctx.wrap_socket(raw) as tls:
                    tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")  # make sure the hub side finished too
                    try:
                        tls.recv(1)
                    except OSError:
                        pass
            compare("listener", hub_log, peer_log)

            https_log = tmp / "browser-keys.log"
            hctx = ssl._create_unverified_context()
            hctx.keylog_filename = str(https_log)
            with urllib.request.urlopen(f"https://127.0.0.1:{hub.http_port}/health", timeout=5, context=hctx) as r:
                body = json.loads(r.read())
            record("/health tls_keylog true with the option", body.get("tls_keylog") is True)
            time.sleep(0.5)
            https_sessions = set(keylog_lines(https_log))
            record("HTTPS status page secrets NOT in the key log (BACnet/SC only)",
                   bool(https_sessions) and not (https_sessions & set(keylog_lines(hub_log))))
        finally:
            hub.stop()

        # 2: connector - the hub dials a TLS server run here (the hub's own
        # certificate, signed by the issuer the hub trusts, SAN 127.0.0.1).
        server_log = tmp / "server-keys.log"
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.minimum_version = ssl.TLSVersion.TLSv1_3
        sctx.load_cert_chain(cert_paths.hub_certificate(certs), cert_paths.hub_private_key(certs))
        sctx.keylog_filename = str(server_log)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(20)
        port = listener.getsockname()[1]
        handshakes = []

        def serve():
            try:
                conn, _ = listener.accept()
                with sctx.wrap_socket(conn, server_side=True) as tls:
                    handshakes.append(tls.version())
                    tls.settimeout(2)
                    try:
                        tls.recv(4096)  # the WebSocket upgrade request
                    except OSError:
                        pass
            except OSError as exc:
                handshakes.append(f"error: {exc}")

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        connector_log = tmp / "connector-keys.log"
        hub = Hub(exe, certs, tmp, "--sc-keylog-file", str(connector_log), "--sc-hub-uri",
                  f"wss://127.0.0.1:{port}/")
        try:
            thread.join(25)
            record("connector completed a TLS handshake with the test server",
                   bool(handshakes) and handshakes[0] == "TLSv1.3", str(handshakes))
            compare("connector", connector_log, server_log)
        finally:
            hub.stop()
            listener.close()

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
