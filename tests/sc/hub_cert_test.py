#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""The hub's own certificate: the start-up certificate request, and --import-cari.

The hub never signs certificates. It makes its own key and a CARI request
(ANSI/ASHRAE 135-2024 Annex AA.2), a Certificate Authority signs it, and the
hub installs the CA's CARI response. This test plays the CA with the
`cryptography` package. It runs the executable itself in a temporary folder:

  1. The first start-up with an empty certificate folder writes
     cert1/device-<n>/port-2/{key,csr}-hub.pem, the hub/ marker, and
     hub-cari-request.zip holding the CSR and NO key, and logs one line naming
     the zip's full path. The CSR asks for serverAuth+clientAuth, localhost,
     127.0.0.1 and this computer's IPv4 address. Later start-ups never
     overwrite the zip (they log that it already exists) and never replace the
     key: with the zip deleted it is made again from the same CSR, and a key
     without a CSR is left alone (no new key, no zip).
  2. --import-cari refuses: a response for another key, one with no issuer,
     one whose issuer didn't sign it, an expired certificate, a zip with a
     "../" path, and the request zip itself. Nothing is written.
  3. --import-cari installs a good response (opr-hub.pem, iss-1.pem, and
     iss-2.pem when the CA sends two), and the hub then serves BACnet/SC.
  4. Options this example doesn't have - signing, and the production
     conveniences of a production hub - are refused as unknown.

    python tests/sc/hub_cert_test.py --exe build/BACnetExampleBSCHUB

Exit code 0 = every check passed.
"""
import argparse
import datetime
import io
import os
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RESULTS = []
HUB_INSTANCE = 389022


def record(name, ok, detail=""):
    ok = bool(ok)
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def last_line(out):
    return out.strip().splitlines()[-1] if out.strip() else ""


def run(exe, cert_dir, *args, env=None):
    # In the certificate folder's parent (a temporary folder), so the hub's
    # logs/ folder is made there.
    proc = subprocess.run([str(exe), "--sc-cert-dir", str(cert_dir), *args], capture_output=True, text=True,
                          timeout=60, stdin=subprocess.DEVNULL, cwd=str(Path(cert_dir).parent), env=env)
    return proc.returncode, proc.stdout + proc.stderr


def start_once(exe, cert_dir):
    """Starts the hub and lets it stop by itself after 3 seconds (the test-only run
    limit, BSCHUB_TEST_RUN_LIMIT_SECONDS). Returns (exit code, output)."""
    env = dict(os.environ, BSCHUB_TEST_RUN_LIMIT_SECONDS="3")
    return run(exe, cert_dir, "--sc-port", str(free_port()), env=env)


def request_line(out):
    """The start-up log line about the certificate request."""
    return next((line for line in out.splitlines() if "certificate request:" in line), "")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_ca(name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def sign(csr_or_key, ca, days=825, expired=False):
    """A hub certificate for a CSR (or a bare public key), signed by ca = (key, cert)."""
    ca_key, ca_cert = ca
    public_key = csr_or_key.public_key()
    subject = csr_or_key.subject if hasattr(csr_or_key, "subject") else x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "someone else")])
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(days=10 if expired else 0, hours=1)
    end = now - datetime.timedelta(days=1) if expired else now + datetime.timedelta(days=days)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(public_key)
            .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def response_zip(path, files):
    """A CARI response zip: {name: bytes}."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True, help="path to BACnetExampleBSCHUB")
    args = parser.parse_args()
    exe = Path(args.exe).resolve()

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        certs = tmp / "certs"
        port = f"cert1/device-{HUB_INSTANCE}/port-2"
        hub_dir = certs / port

        # 1. The certificate request, made at start-up
        request_path = certs / "hub-cari-request.zip"
        rc, out = start_once(exe, certs)
        line = request_line(out)
        record("the first start-up runs and stops by itself (exit 0)", rc == 0, last_line(out))
        record("it logs one line: the request was created, with its full path",
               "created" in line and str(request_path.resolve()) in line and
               sum("certificate request:" in x for x in out.splitlines()) == 1, line)
        record("it writes key-hub.pem, csr-hub.pem and the hub/ marker",
               (hub_dir / "key-hub.pem").is_file() and (hub_dir / "csr-hub.pem").is_file() and
               (hub_dir / "hub").is_dir())
        record("it writes no certificate", not (hub_dir / "opr-hub.pem").exists())
        with zipfile.ZipFile(request_path) as z:
            names = z.namelist()
            csr_bytes = z.read(f"{port}/csr-hub.pem")
        record("hub-cari-request.zip holds the CSR and the hub/ marker",
               f"{port}/csr-hub.pem" in names and f"{port}/hub/" in names, ", ".join(names))
        record("hub-cari-request.zip holds no private key", not any("key-" in n for n in names))
        csr = x509.load_pem_x509_csr(csr_bytes)
        record("the zip's CSR is the one on disk", csr_bytes == (hub_dir / "csr-hub.pem").read_bytes())
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            eku = list(csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        except x509.ExtensionNotFound:
            san, eku = None, []
        ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] if san is not None else []
        record("the CSR asks for localhost and 127.0.0.1 in subjectAltName",
               san is not None and "localhost" in san.get_values_for_type(x509.DNSName) and "127.0.0.1" in ips,
               ", ".join(ips))
        record("the CSR asks for serverAuth and clientAuth",
               ExtendedKeyUsageOID.SERVER_AUTH in eku and ExtendedKeyUsageOID.CLIENT_AUTH in eku)
        record("the CSR's subject is the device name",
               csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Chipkin Example B-SCHUB")
        key_before = (hub_dir / "key-hub.pem").read_bytes()
        zip_before = request_path.read_bytes()
        stat_before = request_path.stat().st_mtime_ns
        time.sleep(1.1)  # so a rewrite would show in the modification time
        rc, out = start_once(exe, certs)
        line = request_line(out)
        record("a second start-up logs that the request already exists, with its full path",
               "already exists" in line and str(request_path.resolve()) in line, line)
        record("... and does not overwrite it",
               request_path.read_bytes() == zip_before and request_path.stat().st_mtime_ns == stat_before)
        record("... and keeps the key", (hub_dir / "key-hub.pem").read_bytes() == key_before)
        request_path.unlink()
        rc, out = start_once(exe, certs)
        with zipfile.ZipFile(request_path) as z:
            remade_csr = z.read(f"{port}/csr-hub.pem")
        record("with the zip deleted, a start-up makes it again from the same CSR and key",
               "created" in request_line(out) and remade_csr == csr_bytes and
               (hub_dir / "key-hub.pem").read_bytes() == key_before, request_line(out))
        # A key without its CSR: the key is never replaced, so no request either.
        lone = tmp / "lone"
        lone_port = lone / port
        lone_port.mkdir(parents=True)
        (lone_port / "key-hub.pem").write_bytes(key_before)
        rc, out = start_once(exe, lone)
        record("a key without a CSR is left alone: no new key, no request, a warning",
               rc == 0 and (lone_port / "key-hub.pem").read_bytes() == key_before and
               not (lone_port / "csr-hub.pem").exists() and not (lone / "hub-cari-request.zip").exists() and
               "not made" in request_line(out), request_line(out))

        # 2. --import-cari refusals
        ca = make_ca("Test Site CA")
        other_ca = make_ca("Another CA")
        good = sign(csr, ca)
        bad_cases = {
            "a certificate for another key": {
                f"{port}/csr-hub.pem": csr_bytes,
                f"{port}/opr-hub.pem": pem(sign(ec.generate_private_key(ec.SECP256R1()), ca)),
                "cert1/issuer/iss-1.pem": pem(ca[1])},
            "no issuer certificate": {
                f"{port}/csr-hub.pem": csr_bytes, f"{port}/opr-hub.pem": pem(good)},
            "an issuer that didn't sign it": {
                f"{port}/csr-hub.pem": csr_bytes, f"{port}/opr-hub.pem": pem(good),
                "cert1/issuer/iss-1.pem": pem(other_ca[1])},
            "an expired certificate": {
                f"{port}/csr-hub.pem": csr_bytes, f"{port}/opr-hub.pem": pem(sign(csr, ca, expired=True)),
                "cert1/issuer/iss-1.pem": pem(ca[1])},
            "a '../' path": {
                f"{port}/opr-hub.pem": pem(good), "cert1/issuer/iss-1.pem": pem(ca[1]),
                "cert1/../../evil.pem": b"x"},
        }
        for name, files in bad_cases.items():
            path = response_zip(tmp / "bad.zip", files)
            rc, out = run(exe, certs, "--import-cari", str(path))
            record(f"--import-cari refuses {name}", rc != 0 and not (hub_dir / "opr-hub.pem").exists(),
                   last_line(out))
        rc, out = run(exe, certs, "--import-cari", str(request_path))
        record("--import-cari refuses the request zip itself", rc != 0, last_line(out))

        # 3. --import-cari, a good response with two issuers
        good_path = response_zip(tmp / "response.zip", {
            f"{port}/csr-hub.pem": csr_bytes, f"{port}/opr-hub.pem": pem(good),
            "cert1/issuer/iss-1.pem": pem(other_ca[1]), "cert1/issuer/iss-2.pem": pem(ca[1]),
            "cert1/response-notes.txt": b"signed by the test"})
        rc, out = run(exe, certs, "--import-cari", str(good_path))
        record("--import-cari installs a good response", rc == 0, last_line(out))
        record("opr-hub.pem is the CA's certificate", (hub_dir / "opr-hub.pem").read_bytes() == pem(good))
        record("iss-1.pem is the issuer that signed it (listed second in the zip)",
               (certs / "cert1/issuer/iss-1.pem").read_bytes() == pem(ca[1]))
        record("iss-2.pem is the other issuer", (certs / "cert1/issuer/iss-2.pem").read_bytes() == pem(other_ca[1]))
        record("the key is unchanged", (hub_dir / "key-hub.pem").read_bytes() == key_before)

        sc_port = free_port()
        hub = subprocess.Popen([str(exe), "--sc-cert-dir", str(certs), "--sc-port", str(sc_port)],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True,
                               cwd=str(tmp))
        listening = False
        try:
            deadline = time.time() + 20
            while time.time() < deadline and not listening:
                try:
                    with socket.create_connection(("127.0.0.1", sc_port), timeout=0.5):
                        listening = True
                except OSError:
                    time.sleep(0.3)
        finally:
            hub.terminate()
            try:
                output = hub.communicate(timeout=10)[0]
            except subprocess.TimeoutExpired:
                hub.kill()
                output = hub.communicate()[0]
        record("the hub serves BACnet/SC with the imported certificate", listening,
               "" if listening else last_line(output))

        # 4. Options this example doesn't have are refused as unknown: signing,
        # and the production conveniences (HTTP, service, config and log files,
        # the hub connector, more connections, ...), BACnet/IP (--port) and
        # --generate-csr (the request is made at start-up).
        for option in (["--port", "47808"], ["--generate-csr"], ["--generate-certs"], ["--add-client-certs"], ["--sign-csr", "x.zip"],
                       ["--migrate-certs"], ["--inspect", "x.pem"], ["--cert-hub-uri", "wss://h:1/"],
                       ["--config", "x.conf"], ["--http-port", "8080"], ["--http-bind", "0.0.0.0"],
                       ["--sc-hub-uri", "wss://h:1/"], ["--sc-failover-uri", "wss://h:1/"],
                       ["--sc-accept-hub-without-hello"], ["--sc-keylog-file", "k.log"],
                       ["--sc-max-hub-connections", "4"], ["--sc-rate-limit", "5"],
                       ["--log-file", "hub.log"], ["--service"], ["--install-service"],
                       ["--device-name", "x"], ["--bacnet-ip", "off"],
                       ["--ip-network-number", "1"], ["--dcc-password", "x"], ["--demo-stop-after", "5"],
                       ["--xml"]):
            rc, out = run(exe, certs, *option)
            record(f"{option[0]} is refused as unknown", rc != 0 and "unknown" in out, last_line(out))

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
