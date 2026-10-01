#!/usr/bin/env python3
"""
Checks the hub's CARI support (Certificate Authority Requirements Interchange,
ANSI/ASHRAE 135-2024 Annex AA.2 - Addendum cs to 135-2020; issue #71). Runs the
executable itself in a temporary folder; the request zips are built here with
Python's zipfile, the way another vendor's tool (e.g. BACCARI) would.

    python tests/sc/cari_test.py --exe build/Release/BACnetExampleBSCHUB.exe

  1. A site request: device-100 (two ports, one a hub function: hub/),
     device-200 (a router: router/, with an optional key-<name>.pem), device-300
     (a CSR with a broken signature), plus vendor-data and request-notes.txt.
     --sign-csr site-request.zip writes site-response.zip and exits 1 (one
     refused). The response keeps every request file and empty folder byte for
     byte, adds opr-<name>.pem next to each good CSR (signed by iss-1, the CSR's
     subject and key; serverAuth too on the hub port), cert1/issuer/iss-1.pem
     (the hub's), errors.txt (one tab-separated line: device-300, port-1, why)
     and response-notes.txt.
  2. A clean request exits 0 and has no errors.txt; a re-submitted response is
     accepted, its old opr-/errors.txt replaced.
  3. A key-<name>.pem that isn't the CSR's key is refused for that CSR.
  4. Refused outright (exit != 0, no response file): not a zip, '..' in a path,
     a file CARI doesn't name, a folder that isn't device-<n>, no cert1/ root,
     an <id> with '?', vendor-data over 1 MB, a zip over 4 MB, no CSR at all.
  5. The hub accepts a CARI-signed certificate: a TLS 1.3 handshake with
     device-200's opr-/key- files against a running hub.
  6. Older folders: a 1.4-style flat folder still runs (the log names the
     layout); --migrate-certs copies it into cert1/ + ca/ byte for byte, leaves
     the old files alone, refuses a second time, and the hub runs on the result.

Exit code 0 = every check passed.
"""
import argparse
import io
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import cert_paths

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def last_line(out):
    return out.strip().splitlines()[-1] if out.strip() else ""


def run(exe, cert_dir, *args):
    proc = subprocess.run([str(exe), "--sc-cert-dir", str(cert_dir), *args], capture_output=True, text=True,
                          timeout=60, stdin=subprocess.DEVNULL)
    return proc.returncode, proc.stdout + proc.stderr


def pem(obj):
    return obj.public_bytes(serialization.Encoding.PEM)


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def csr_for(key, cn):
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Site"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])).sign(key, hashes.SHA256())


def make_zip(entries):
    """entries: {name: bytes or None (a folder)}"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            if data is None:
                z.writestr(zipfile.ZipInfo(name if name.endswith("/") else name + "/"), b"")
            else:
                z.writestr(name, data)
    return buf.getvalue()


def read_zip(path):
    with zipfile.ZipFile(path) as z:
        return {n: (None if n.endswith("/") else z.read(n)) for n in z.namelist()}


def eku(cert):
    try:
        return set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    except x509.ExtensionNotFound:
        return set()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Hub:
    def __init__(self, exe, cert_dir, tmp):
        self.log = tmp / f"hub-{time.time_ns()}.log"
        self.sc_port = free_port()
        self.out = self.log.open("w")
        self.proc = subprocess.Popen([str(exe), "--port", str(free_port()), "--sc-port", str(self.sc_port),
                                      "--http-port", str(free_port()), "--sc-cert-dir", str(cert_dir)],
                                     stdout=self.out, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

    def output(self):
        return self.log.read_text(errors="replace") if self.log.exists() else ""

    def wait_listening(self, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            if "listening for WebSocket/TLS connections" in self.output():
                return True
            time.sleep(0.1)
        return False

    def stop(self):
        self.proc.kill()
        self.proc.wait()
        self.out.close()


def tls_handshake(port, certfile, keyfile, cafile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.load_verify_locations(str(cafile))
    ctx.load_cert_chain(str(certfile), str(keyfile))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, ctx.wrap_socket(raw) as tls:
            # In TLS 1.3 the server judges our certificate after the handshake:
            # a refusal arrives as an alert on the next read (an SSLError). A
            # read that just times out (the hub waits for a WebSocket upgrade)
            # means it was accepted.
            tls.settimeout(2)
            tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            try:
                tls.recv(1)
            except (socket.timeout, TimeoutError):
                pass
            return True, tls.version()
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True, help="path to BACnetExampleBSCHUB")
    args = parser.parse_args()
    exe = Path(args.exe).resolve()

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        tmp = Path(tmp)
        certs = tmp / "certs"
        rc, out = run(exe, certs, "--generate-certs", "1")
        record("--generate-certs 1", rc == 0, last_line(out))
        iss1 = (certs / "cert1" / "issuer" / "iss-1.pem").read_bytes()
        issuer = x509.load_pem_x509_certificate(iss1)

        # --- 1. A site request -------------------------------------------------
        key_a = ec.generate_private_key(ec.SECP256R1())
        key_hub = ec.generate_private_key(ec.SECP256R1())
        key_b = ec.generate_private_key(ec.SECP384R1())
        key_bad = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        bad_csr = bytearray(csr_for(key_bad, "Broken").public_bytes(serialization.Encoding.DER))
        bad_csr[-5] ^= 0xFF
        bad_pem = b"-----BEGIN CERTIFICATE REQUEST-----\n" + __import__("base64").encodebytes(bytes(bad_csr)) + \
                  b"-----END CERTIFICATE REQUEST-----\n"
        vendor = os.urandom(5000)
        request = {
            "cert1/": None,
            "cert1/vendor-data": vendor,
            "cert1/request-notes.txt": "Site 42, panel A - please sign.\n".encode(),
            "cert1/device-100/": None,
            "cert1/device-100/port-1/": None,
            "cert1/device-100/port-1/csr-ahu.pem": pem(csr_for(key_a, "AHU 1")),
            "cert1/device-100/port-2/": None,
            "cert1/device-100/port-2/hub/": None,
            "cert1/device-100/port-2/csr-hubport.pem": pem(csr_for(key_hub, "AHU 1 hub")),
            "cert1/device-200/": None,
            "cert1/device-200/router/": None,
            "cert1/device-200/port-sc 1/": None,
            "cert1/device-200/port-sc 1/csr-router 1.pem": pem(csr_for(key_b, "Router 1")),
            "cert1/device-200/port-sc 1/key-router 1.pem": key_pem(key_b),
            "cert1/device-300/": None,
            "cert1/device-300/port-1/": None,
            "cert1/device-300/port-1/csr-bad.pem": bad_pem,
        }
        req_path = tmp / "site-request.zip"
        req_path.write_bytes(make_zip(request))
        rc, out = run(exe, certs, "--sign-csr", str(req_path))
        resp_path = tmp / "site-response.zip"
        record("--sign-csr on a CARI zip exits 1 when one CSR is refused", rc == 1, last_line(out))
        record("site-response.zip written next to the request", resp_path.is_file())
        resp = read_zip(resp_path)
        with zipfile.ZipFile(resp_path) as z:
            record("response zip CRCs", z.testzip() is None)
        record("every request file and folder kept byte for byte",
               all(n in resp and resp[n] == d for n, d in request.items()),
               ", ".join(n for n, d in request.items() if resp.get(n, b"<missing>") != d))
        record("cert1/issuer/iss-1.pem is the hub's issuer", resp.get("cert1/issuer/iss-1.pem") == iss1)
        record("no iss-2.pem (the hub has one issuer)", "cert1/issuer/iss-2.pem" not in resp)
        for path, key, cn in (("cert1/device-100/port-1/opr-ahu.pem", key_a, "AHU 1"),
                              ("cert1/device-100/port-2/opr-hubport.pem", key_hub, "AHU 1 hub"),
                              ("cert1/device-200/port-sc 1/opr-router 1.pem", key_b, "Router 1")):
            ok = path in resp
            cert = x509.load_pem_x509_certificate(resp[path]) if ok else None
            record(f"{path} present", ok)
            if cert is not None:
                try:
                    cert.verify_directly_issued_by(issuer)
                    record(f"  signed by iss-1", True)
                except Exception as exc:  # noqa: BLE001
                    record("  signed by iss-1", False, str(exc))
                record("  for the CSR's key", spki(cert.public_key()) == spki(key.public_key()))
                record("  keeps the CSR's subject", cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == cn)
        hub_cert = x509.load_pem_x509_certificate(resp["cert1/device-100/port-2/opr-hubport.pem"])
        node_cert = x509.load_pem_x509_certificate(resp["cert1/device-100/port-1/opr-ahu.pem"])
        record("hub port (hub/) gets serverAuth + clientAuth",
               eku(hub_cert) == {ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH})
        record("ordinary port gets clientAuth", eku(node_cert) == {ExtendedKeyUsageOID.CLIENT_AUTH})
        record("no opr for the broken CSR", "cert1/device-300/port-1/opr-bad.pem" not in resp)
        errors = resp.get("cert1/errors.txt", b"").decode()
        lines = [l for l in errors.splitlines() if l]
        record("errors.txt: one tab-separated line for device-300/port-1",
               len(lines) == 1 and lines[0].split("\t")[:2] == ["device-300", "port-1"] and len(lines[0].split("\t")) == 3,
               repr(errors))
        record("response-notes.txt says 3 signed, 1 refused",
               b"3 signed, 1 refused" in resp.get("cert1/response-notes.txt", b""))
        record("certificates.txt lists the response's certificates",
               (certs / "certificates.txt").read_text().count("site-response.zip:") == 3)

        # --- 2. clean request; re-submitted response ----------------------------
        clean = {k: v for k, v in request.items() if "device-300" not in k}
        (tmp / "clean.zip").write_bytes(make_zip(clean))
        rc, out = run(exe, certs, "--sign-csr", str(tmp / "clean.zip"))
        clean_resp = read_zip(tmp / "clean-response.zip") if (tmp / "clean-response.zip").exists() else {}
        record("a clean request exits 0, no errors.txt", rc == 0 and "cert1/errors.txt" not in clean_resp, last_line(out))
        rc, out = run(exe, certs, "--sign-csr", str(resp_path))
        again = read_zip(tmp / "site-response-response.zip") if (tmp / "site-response-response.zip").exists() else {}
        record("a re-submitted response is signed again (new opr-)",
               rc == 1 and again.get("cert1/device-100/port-1/opr-ahu.pem") not in (None, resp["cert1/device-100/port-1/opr-ahu.pem"]),
               last_line(out))

        # --- 3. a key- that isn't the CSR's ------------------------------------
        mixed = {"cert1/device-5/port-1/csr-x.pem": pem(csr_for(key_a, "X")),
                 "cert1/device-5/port-1/key-x.pem": key_pem(key_b)}
        (tmp / "mixed.zip").write_bytes(make_zip(mixed))
        rc, out = run(exe, certs, "--sign-csr", str(tmp / "mixed.zip"))
        m = read_zip(tmp / "mixed-response.zip") if (tmp / "mixed-response.zip").exists() else {}
        record("key-x.pem that isn't the CSR's key: refused in errors.txt",
               rc == 1 and "cert1/device-5/port-1/opr-x.pem" not in m and b"not the key" in m.get("cert1/errors.txt", b""))

        # --- 4. refused outright --------------------------------------------------
        good = pem(csr_for(key_a, "Y"))
        cases = {
            "not a zip": b"this is not a zip",
            "'..' in a path": make_zip({"cert1/device-1/port-1/../../../evil/csr-a.pem": good}),
            "a file CARI doesn't name": make_zip({"cert1/device-1/port-1/csr-a.pem": good,
                                                  "cert1/device-1/port-1/readme.txt": b"hi"}),
            "a folder that isn't device-<n>": make_zip({"cert1/dev-1/port-1/csr-a.pem": good}),
            "no cert1/ root": make_zip({"device-1/port-1/csr-a.pem": good}),
            "an <id> with '?'": make_zip({"cert1/device-1/port-a?b/csr-a.pem": good}),
            "vendor-data over 1 MB": make_zip({"cert1/vendor-data": b"x" * (1024 * 1024 + 1),
                                               "cert1/device-1/port-1/csr-a.pem": good}),
            "a zip over 4 MB": None,
            "no CSR at all": make_zip({"cert1/device-1/port-1/": None}),
            "device instance 4194303": make_zip({"cert1/device-4194303/port-1/csr-a.pem": good}),
        }
        big = io.BytesIO()
        with zipfile.ZipFile(big, "w", zipfile.ZIP_STORED) as z:
            z.writestr("cert1/vendor-data", os.urandom(4 * 1024 * 1024 + 100))
        cases["a zip over 4 MB"] = big.getvalue()
        for name, data in cases.items():
            path = tmp / "refused-request.zip"
            path.write_bytes(data)
            out_path = tmp / "refused-response.zip"
            if out_path.exists():
                out_path.unlink()
            rc, out = run(exe, certs, "--sign-csr", str(path))
            record(f"refused: {name}", rc != 0 and not out_path.exists(), last_line(out)[:150])

        # --- 5. the hub accepts a CARI-signed certificate ------------------------
        router_dir = tmp / "router"
        (router_dir).mkdir()
        (router_dir / "opr.pem").write_bytes(resp["cert1/device-200/port-sc 1/opr-router 1.pem"])
        (router_dir / "key.pem").write_bytes(key_pem(key_b))
        hub = Hub(exe, certs, tmp)
        try:
            record("hub starts on the CARI set", hub.wait_listening())
            ok, detail = tls_handshake(hub.sc_port, router_dir / "opr.pem", router_dir / "key.pem",
                                       certs / "cert1" / "issuer" / "iss-1.pem")
            record("TLS 1.3 handshake with a certificate from the CARI response", ok, detail)
            # Control: the same check must FAIL for a device another CA signed,
            # or the line above proves nothing.
            other = tmp / "other-ca"
            run(exe, other, "--generate-certs", "1")
            o_opr, o_key = cert_paths.client_files(other, "client-01")
            ok, detail = tls_handshake(hub.sc_port, o_opr, o_key, certs / "cert1" / "issuer" / "iss-1.pem")
            record("control: a device signed by another CA is refused", not ok, detail[:120])
        finally:
            hub.stop()

        # --- 6. older folders and --migrate-certs --------------------------------
        flat = tmp / "flat"
        flat.mkdir()
        port = cert_paths.hub_port_folder(certs)
        shutil.copy(port / "opr-hub.pem", flat / "operational-certificate.pem")
        shutil.copy(port / "key-hub.pem", flat / "private-key.pem")
        shutil.copy(port / "csr-hub.pem", flat / "certificate-signing-request.pem")
        shutil.copy(certs / "cert1" / "issuer" / "iss-1.pem", flat / "issuer-certificate.pem")
        shutil.copy(certs / "ca" / "ca-key.pem", flat / "issuer-private-key.pem")
        client_opr, client_key = cert_paths.client_files(certs, "client-01")
        before = {p.name: p.read_bytes() for p in flat.iterdir()}
        hub = Hub(exe, flat, tmp)
        try:
            record("a 1.4-style flat folder still runs", hub.wait_listening())
            record("the log names the flat layout", "flat names from 1.4" in hub.output())
            ok, detail = tls_handshake(hub.sc_port, client_opr, client_key, flat / "issuer-certificate.pem")
            record("a device connects to the flat-layout hub", ok, detail)
        finally:
            hub.stop()
        rc, out = run(exe, flat, "--migrate-certs")
        record("--migrate-certs exits 0", rc == 0, last_line(out))
        mport = cert_paths.hub_port_folder(flat)
        record("migrated: cert1/device-<n>/port-2/hub/ exists", mport is not None and (mport / "hub").is_dir())
        if mport is not None:
            record("migrated files are byte-identical copies",
                   (mport / "opr-hub.pem").read_bytes() == before["operational-certificate.pem"] and
                   (mport / "key-hub.pem").read_bytes() == before["private-key.pem"] and
                   (mport / "csr-hub.pem").read_bytes() == before["certificate-signing-request.pem"] and
                   (flat / "cert1" / "issuer" / "iss-1.pem").read_bytes() == before["issuer-certificate.pem"] and
                   (flat / "ca" / "ca-key.pem").read_bytes() == before["issuer-private-key.pem"] and
                   (flat / "ca" / "ca-cert.pem").read_bytes() == before["issuer-certificate.pem"])
        record("old files left alone", all((flat / n).read_bytes() == b for n, b in before.items()))
        rc, out = run(exe, flat, "--migrate-certs")
        record("--migrate-certs refuses a second time", rc != 0, last_line(out))
        hub = Hub(exe, flat, tmp)
        try:
            record("the migrated folder runs, as CARI", hub.wait_listening() and "CARI (cert1/) layout" in hub.output())
            ok, detail = tls_handshake(hub.sc_port, client_opr, client_key, flat / "cert1" / "issuer" / "iss-1.pem")
            record("a device connects to the migrated hub", ok, detail)
        finally:
            hub.stop()
        rc, out = run(exe, flat, "--add-client-certs", "1")
        record("--add-client-certs works on the migrated folder (signs with ca/)", rc == 0, last_line(out))

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
