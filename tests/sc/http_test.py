#!/usr/bin/env python3
"""
HTTP endpoint checks: the status page, /health, /metrics and the certificate
upload (POST /certs/<slot>).

Start the hub with an upload token in a config file, then run this:

    BACnetExampleBSCHUB --generate-certs 1
    printf 'http-upload-token = test-token-123\\n' > http-test.conf
    BACnetExampleBSCHUB --config http-test.conf --http-port 18080
    python tests/sc/http_test.py --http-port 18080 --token test-token-123 --cert-dir certs

Checks:
  - GET / is HTML with the version and (with --device-name) the device name
  - GET /health is JSON with "status", HTTP 200 when ok / 503 when degraded
  - GET /metrics is JSON with the counters
  - unknown path -> 404
  - POST without the token -> 401; with a wrong token -> 401
  - POST a body that isn't a certificate -> 400, and the file on disk is unchanged
  - POST the hub's own issuer certificate back to issuer1 -> 200 (validated and
    saved: re-uploading the same CA changes nothing but proves the happy path)
  - POST something that isn't a certificate request to csr -> 400
  - more than 5 attempts a minute from one address -> 429 (run last)

Without --token, only checks that the upload is disabled (503).

Exit code 0 = every check passed.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import cert_paths

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def request(base, path, method="GET", body=None, token=None):
    req = urllib.request.Request(base + path, data=body, method=method)
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--token", default=None, help="the hub's http-upload-token (omit: upload must be disabled)")
    parser.add_argument("--cert-dir", default="certs")
    parser.add_argument("--device-name", default=None, help="expect this name on the status page")
    args = parser.parse_args()
    base = f"http://{args.host}:{args.http_port}"
    cert_dir = Path(args.cert_dir)

    status, page = request(base, "/")
    version = None
    main_cpp = Path(__file__).resolve().parents[2] / "main.cpp"
    for line in main_cpp.read_text(encoding="utf-8").splitlines():
        if 'APP_VERSION = "' in line:
            version = line.split('"')[1]
    record("GET / is the status page with the version", status == 200 and f"Version {version}" in page,
           f"HTTP {status}")
    if args.device_name:
        record("GET / shows --device-name", args.device_name in page)

    status, body = request(base, "/health")
    try:
        health = json.loads(body)
    except ValueError:
        health = {}
    record("GET /health is JSON with a status", health.get("status") in ("ok", "degraded"), body)
    record("GET /health HTTP code matches the status",
           (health.get("status") == "ok" and status == 200) or (health.get("status") == "degraded" and status == 503),
           f"HTTP {status}")

    status, body = request(base, "/metrics")
    try:
        metrics = json.loads(body)
    except ValueError:
        metrics = {}
    record("GET /metrics has the counters", status == 200 and all(
        k in metrics for k in ("uptime_seconds", "sc_total_connects", "sc_rx_messages", "sc_tx_queue_overflows")),
        body)

    status, _ = request(base, "/no-such-page")
    record("unknown path -> 404", status == 404, f"HTTP {status}")

    issuer = cert_paths.issuer_certificate(cert_dir)
    issuer_pem = issuer.read_bytes()

    if args.token is None:
        status, body = request(base, "/certs/issuer1", "POST", issuer_pem, token="anything")
        record("upload disabled without http-upload-token -> 503", status == 503, f"HTTP {status}: {body.strip()}")
    else:
        status, _ = request(base, "/certs/issuer1", "POST", issuer_pem)
        record("upload without a token -> 401", status == 401, f"HTTP {status}")
        status, _ = request(base, "/certs/issuer1", "POST", issuer_pem, token=args.token + "x")
        record("upload with a wrong token -> 401", status == 401, f"HTTP {status}")

        before = issuer.read_bytes()
        junk = b"-----BEGIN CERTIFICATE-----\nnot really a certificate at all, just text\n-----END CERTIFICATE-----\n"
        status, body = request(base, "/certs/issuer1", "POST", junk, token=args.token)
        record("upload of a malformed certificate -> 400", status == 400, f"HTTP {status}: {body.strip()}")
        record("... and the file on disk is unchanged", issuer.read_bytes() == before)

        status, body = request(base, "/certs/issuer1", "POST", issuer_pem, token=args.token)
        record("upload of a valid issuer certificate -> 200", status == 200, f"HTTP {status}: {body.strip()}")

        status, body = request(base, "/certs/csr", "POST", issuer_pem, token=args.token)
        record("upload of something that isn't a CSR to csr -> 400", status == 400, f"HTTP {status}: {body.strip()}")

        # 5 attempts so far from this address; the 6th within the minute is refused.
        status, body = request(base, "/certs/operational", "POST", issuer_pem, token=args.token)
        record("6th upload attempt in a minute -> 429", status == 429, f"HTTP {status}: {body.strip()}")

    failed = [name for name, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
