#!/usr/bin/env python3
"""
Checks the certificate set-up guide (GET /setup and /api/..., issue #72). Runs
the executable itself on free ports in a temporary folder; needs no running hub.

    python tests/sc/setup_portal_test.py --exe build/Release/BACnetExampleBSCHUB.exe

Hub A - the default lab set (the hub key has NO password):
  - GET /setup serves the page (CSP header, no external resources), in full
    also when the browser asks for gzip (Accept-Encoding; chunked transfer);
  - GET /api/setup/info: hub URIs, every field and check of the hub's and the
    CA's certificates (all pass), the gate says "loopback only, allowed";
  - POST /api/inspect recognises a certificate, a CSR, a private key (and that
    it matches the certificate in the same upload), a CARI zip, a .pfx, and
    garbage - with the right checks failing (another CA's certificate: "Signed
    by this hub's CA" fails with OpenSSL's reason);
  - POST /api/sign from loopback: a bare CSR -> clients/<label>/ with the CARI
    response; a CARI request -> a CARI response zip; a weak CSR refused;
  - POST /api/generate -> a device folder whose opr-/key- files complete a
    BACnet/SC WebSocket handshake with the hub, and GET /api/diagnostics then
    shows that device "connected";
  - a device signed by ANOTHER CA is refused, and /api/diagnostics records it
    as "tls-refused" with OpenSSL's reason;
  - downloads: public files from loopback; '..' paths refused;
  - from a non-loopback address (the hub's HTTP bound to this computer's LAN
    address) signing is refused with 403 - no password exists.
Hub B - the hub key encrypted, sc-key-password in the config file:
  - signing needs the password from loopback too: none -> 401, wrong -> 401,
    right -> 200; private downloads too; /api/check-password;
  - after 5 wrong passwords from one address -> 429;
  - over plain HTTP from a non-loopback address -> 403 even with the password.

Exit code 0 = every check passed.
"""
import argparse
import base64
import gzip
import io
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
import zlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

import cert_paths

RESULTS = []


def record(name, ok, detail=""):
    ok = bool(ok)
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def lan_address():
    """An address of this computer that isn't loopback, or None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # no packet is sent for UDP connect
            ip = s.getsockname()[0]
            return None if ip.startswith("127.") else ip
    except OSError:
        return None


def csr_pem(key, cn):
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn)])).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class Hub:
    def __init__(self, exe, cert_dir, tmp, *extra, http_bind=None):
        self.log = tmp / f"hub-{time.time_ns()}.log"
        self.http_port = free_port()
        self.sc_port = free_port()
        args = [str(exe), "--port", str(free_port()), "--sc-port", str(self.sc_port), "--http-port",
                str(self.http_port), "--sc-cert-dir", str(cert_dir), *extra]
        if http_bind:
            args += ["--http-bind", http_bind]
        self.host = http_bind or "127.0.0.1"
        self.out = self.log.open("w")
        self.proc = subprocess.Popen(args, stdout=self.out, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

    def output(self):
        return self.log.read_text(errors="replace") if self.log.exists() else ""

    def wait(self):
        end = time.time() + 30
        while time.time() < end:
            if "listening for WebSocket/TLS connections" in self.output() and "set-up guide" in self.output():
                return True
            time.sleep(0.1)
        return False

    def call(self, path, method="GET", body=None, password=None, headers=None):
        req = urllib.request.Request(f"http://{self.host}:{self.http_port}{path}", data=body, method=method)
        if password == "":
            req.add_header("Authorization", "HubKey -")  # what the page sends with no password
        elif password is not None:
            req.add_header("Authorization", "HubKey " + base64.b64encode(password.encode()).decode())
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def json(self, path, method="GET", body=None, password=None, headers=None):
        status, headers, data = self.call(path, method, body, password, headers)
        try:
            return status, json.loads(data)
        except ValueError:
            return status, {"_raw": data[:200]}

    def stop(self):
        self.proc.kill()
        self.proc.wait()
        self.out.close()


def ws_handshake(port, certfile, keyfile, cafile):
    """A BACnet/SC WebSocket upgrade over mutual TLS. True if the hub answered 101."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.load_verify_locations(str(cafile))
    ctx.load_cert_chain(str(certfile), str(keyfile))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, ctx.wrap_socket(raw) as tls:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
                        b"Sec-WebSocket-Protocol: hub.bsc.bacnet.org\r\n\r\n")
            reply = tls.recv(1024)
            time.sleep(0.3)
            return b" 101 " in reply.split(b"\r\n", 1)[0], reply[:40]
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def checks_of(item):
    return {c["name"]: c["status"] for c in item["checks"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True)
    args = parser.parse_args()
    exe = Path(args.exe).resolve()
    lan = lan_address()

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        tmp = Path(tmp)
        certs = tmp / "certs"
        other = tmp / "other"
        for d in (certs, other):
            subprocess.run([str(exe), "--sc-cert-dir", str(d), "--generate-certs", "1"], check=True,
                           capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        issuer = cert_paths.issuer_certificate(certs)

        # --inspect on the command line: the same checks as the page.
        o_opr, _ = cert_paths.client_files(other, "client-01")
        proc = subprocess.run([str(exe), "--sc-cert-dir", str(certs), "--inspect", str(o_opr)], capture_output=True,
                              text=True, timeout=60, stdin=subprocess.DEVNULL)
        record("--inspect: another CA's certificate -> exit 1, says why and what to do",
               proc.returncode == 1 and "[FAIL] Signed by this hub's CA" in proc.stdout and "->" in proc.stdout)
        proc = subprocess.run([str(exe), "--sc-cert-dir", str(certs), "--inspect",
                               str(certs / "clients" / "client-01" / "client-01-cari-response.zip")],
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        record("--inspect: its own CARI response -> exit 0, every check passes", proc.returncode == 0 and
               "All checks passed" in proc.stdout, proc.stdout.splitlines()[0] if proc.stdout else "")

        # ======================= hub A: no key password =========================
        hub = Hub(exe, certs, tmp)
        try:
            started = hub.wait()
            record("hub A starts (and logs the guide's URL)", started, "" if started else hub.output()[-800:])
            if not started:
                return 1
            status, headers, page = hub.call("/setup")
            record("GET /setup serves the page", status == 200 and b"BACnet/SC set-up guide" in page, f"{len(page)} bytes")
            record("  with a Content-Security-Policy", "default-src 'none'" in headers.get("content-security-policy", ""))
            record("  and no external resources", b"http://" not in page.split(b"<script>")[0].replace(b"http://127", b"")
                   and b"src=\"http" not in page and b"href=\"http" not in page.replace(b"href=\"https://", b""))
            # What a browser sends. lws then compresses and switches to chunked
            # transfer encoding - the case that once cut the page short.
            raw = socket.create_connection(("127.0.0.1", hub.http_port), timeout=10)
            raw.sendall(b"GET /setup HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n"
                        b"Accept-Encoding: gzip, deflate, br\r\n\r\n")
            data = b""
            while True:
                chunk = raw.recv(65536)
                if not chunk:
                    break
                data += chunk
            raw.close()
            head, _, rest = data.partition(b"\r\n\r\n")
            chunked = b"transfer-encoding: chunked" in head.lower()
            body = b""
            while chunked and rest:
                size_line, _, rest = rest.partition(b"\r\n")
                size = int(size_line.split(b";")[0], 16)
                if size == 0:
                    break
                body += rest[:size]
                rest = rest[size + 2:]
            encoding = "identity"
            for line in head.decode(errors="replace").split("\r\n"):
                if line.lower().startswith("content-encoding:"):
                    encoding = line.split(":", 1)[1].strip().lower()
            if not chunked:
                body = rest
            if encoding == "gzip":
                body = gzip.decompress(body)
            elif encoding == "deflate":
                try:
                    body = zlib.decompress(body)                     # zlib-wrapped (RFC 1950)
                except zlib.error:
                    body = zlib.decompressobj(-zlib.MAX_WBITS).decompress(body)  # raw deflate
            record("  in full when a browser asks for compression (chunked)", body == page,
                   f"chunked={chunked}, encoding={encoding}, {len(body)} of {len(page)} bytes")

            status, info = hub.json("/api/setup/info")
            record("GET /api/setup/info", status == 200 and info.get("canSign") is True, info.get("signingProblem", ""))
            record("  names the hub URIs", any(u.endswith(f":{hub.sc_port}/") for u in info.get("hubUris", [])),
                   ", ".join(info.get("hubUris", [])))
            gate = info.get("gate", {})
            record("  gate: no password, loopback, allowed",
                   gate.get("passwordProtectedKey") is False and gate.get("allowedWithoutPassword") is True)
            hub_checks = checks_of(info["hubCertificate"]["items"][0])
            record("  the hub certificate's checks pass",
                   all(v in ("pass", "info") for v in hub_checks.values()) and hub_checks.get("Signed by this hub's CA") == "pass",
                   json.dumps(hub_checks))
            fields = {f["name"] for f in info["hubCertificate"]["items"][0]["fields"]}
            record("  ... with every field (subject, SAN, EKU, fingerprints)",
                   {"Subject", "Issuer", "SHA-256 fingerprint", "Public key"} <= fields and any("Alternative Name" in f for f in fields)
                   and any("Extended Key Usage" in f for f in fields), str(len(fields)))

            # --- inspect --------------------------------------------------------
            dev_opr, dev_key = cert_paths.client_files(certs, "client-01")
            status, j = hub.json("/api/inspect?name=opr.pem", "POST", dev_opr.read_bytes() + dev_key.read_bytes())
            kinds = [i["kind"] for i in j.get("items", [])]
            record("inspect: certificate + key in one PEM", status == 200 and kinds == ["certificate", "private-key"], str(kinds))
            key_checks = checks_of(j["items"][1])
            record("  the key matches the certificate", any(k.startswith("Matches") and v == "pass" for k, v in key_checks.items()),
                   json.dumps(key_checks))
            record("  the certificate is signed by this hub's CA", checks_of(j["items"][0]).get("Signed by this hub's CA") == "pass")
            o_opr, o_key = cert_paths.client_files(other, "client-01")
            status, j = hub.json("/api/inspect?name=other.pem", "POST", o_opr.read_bytes())
            c = [x for x in j["items"][0]["checks"] if x["name"] == "Signed by this hub's CA"][0]
            record("inspect: another CA's certificate FAILS 'Signed by this hub's CA', with OpenSSL's reason and a fix",
                   c["status"] == "fail" and "issuer" in c["detail"] and c["fix"], c["detail"])
            weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
            status, j = hub.json("/api/inspect", "POST", csr_pem(weak, "Weak"))
            record("inspect: a weak CSR - key strength fails",
                   j["items"][0]["kind"] == "csr" and checks_of(j["items"][0]).get("Key strength") == "fail")
            der = x509.load_pem_x509_certificate(dev_opr.read_bytes()).public_bytes(serialization.Encoding.DER)
            status, j = hub.json("/api/inspect", "POST", der)
            record("inspect: DER certificate", j["items"][0]["kind"] == "certificate", j.get("detected", ""))
            status, j = hub.json("/api/inspect", "POST", (certs / "clients" / "client-01" / "client-01.pfx").read_bytes())
            record("inspect: .pfx with an empty password", [i["kind"] for i in j["items"]][:2] == ["pkcs12", "certificate"],
                   j.get("detected", ""))
            status, j = hub.json("/api/inspect", "POST", (certs / "clients" / "client-01" / "client-01-cari-response.zip").read_bytes())
            record("inspect: a CARI response zip", "CARI response" in j.get("detected", "") and j.get("cari", {}).get("valid") is True,
                   j.get("detected", ""))
            status, j = hub.json("/api/inspect", "POST", b"\x00\x01this is not anything")
            record("inspect: garbage is 'not recognised', with a hint", j["items"][0]["kind"] == "unknown" and
                   checks_of(j["items"][0]).get("Recognised") == "fail")

            # --- sign / generate (loopback, no password) -------------------------
            k1 = ec.generate_private_key(ec.SECP256R1())
            status, j = hub.json("/api/sign?label=csrf", "POST", csr_pem(k1, "AHU 7"))
            record("sign WITHOUT the Authorization: HubKey header -> 403 (cross-site request forgery)", status == 403,
                   j.get("error", ""))
            status, j = hub.json("/api/sign?label=rebind", "POST", csr_pem(k1, "AHU 7"), password="",
                                 headers={"Host": f"attacker.example:{hub.http_port}"})
            record("sign with a non-loopback Host (DNS rebinding) -> 403", status == 403, j.get("error", ""))
            status, j = hub.json("/api/sign?label=ahu-7&instance=7007&port=sc&name=ahu7.csr", "POST", csr_pem(k1, "AHU 7"),
                                 password="")
            record("sign a CSR from loopback (no password needed)", status == 200 and j.get("ok") and j.get("label") == "ahu-7",
                   json.dumps(j)[:160])
            names = [d["name"] for d in j.get("downloads", [])]
            record("  the device folder has the CARI files and tools",
                   "cert1/device-7007/port-sc/opr-ahu-7.pem" in names and "ahu-7-cari-response.zip" in names
                   and "bacnetsc.config" in names, ", ".join(names))
            status, j2 = hub.json("/api/sign?label=ahu-7", "POST", csr_pem(k1, "AHU 7"), password="")
            record("  signing into the same name again -> 409", status == 409, j2.get("error", ""))
            status, j = hub.json("/api/sign", "POST", csr_pem(weak, "Weak"), password="")
            record("sign refuses a weak CSR (400, with why)", status == 400 and "RSA 1024" in j.get("error", ""), j.get("error", ""))
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr("cert1/device-50/port-1/csr-vav.pem", csr_pem(ec.generate_private_key(ec.SECP256R1()), "VAV 50"))
                z.writestr("cert1/device-51/port-1/csr-vav.pem", csr_pem(weak, "VAV 51 weak"))
            status, j = hub.json("/api/sign?name=site-request.zip", "POST", buf.getvalue(), password="")
            record("sign a CARI request -> 1 signed, 1 refused, errors.txt",
                   status == 200 and [i["signed"] for i in j.get("items", [])] == [True, False] and "device-51\tport-1" in j.get("errors", ""),
                   json.dumps(j.get("items"))[:160])
            url = j["downloads"][0]["url"]
            status, headers, data = hub.call(url)
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                resp_names = set(z.namelist())
            record("  the CARI response zip downloads, with opr- and issuer/",
                   status == 200 and "cert1/device-50/port-1/opr-vav.pem" in resp_names and "cert1/issuer/iss-1.pem" in resp_names)

            status, j = hub.json("/api/generate?label=tool-1&instance=900", "POST", password="")
            record("generate a device's key and certificate", status == 200 and j.get("ok"), j.get("error", ""))
            dls = {d["name"]: d for d in j.get("downloads", [])}
            key_dl = dls.get("cert1/device-900/port-1/key-tool-1.pem", {})
            record("  the key and .pfx are marked private", key_dl.get("private") is True and dls.get("tool-1.pfx", {}).get("private") is True)
            status, _, opr = hub.call(dls["cert1/device-900/port-1/opr-tool-1.pem"]["url"])
            status2, _, key = hub.call(key_dl["url"], password="")
            record("  public and private files download from loopback", status == 200 and status2 == 200 and b"PRIVATE KEY" in key)
            (tmp / "t1.pem").write_bytes(opr)
            (tmp / "t1.key").write_bytes(key)
            status, d0 = hub.json("/api/diagnostics?after=0")
            last = max([e["sequence"] for e in d0.get("events", [])] + [0])
            ok, detail = ws_handshake(hub.sc_port, tmp / "t1.pem", tmp / "t1.key", issuer)
            record("  the generated files complete a BACnet/SC WebSocket handshake with the hub", ok, str(detail))
            time.sleep(0.5)
            status, d1 = hub.json(f"/api/diagnostics?after={last}")
            kinds = [e["kind"] for e in d1.get("events", [])]
            record("  /api/diagnostics shows it: tcp, then connected with its certificate",
                   "tcp" in kinds and "connected" in kinds and any("tool-1" in e["subject"] for e in d1["events"] if e["kind"] == "connected"),
                   str(kinds))
            ok, detail = ws_handshake(hub.sc_port, o_opr, o_key, issuer)
            time.sleep(0.5)
            status, d2 = hub.json(f"/api/diagnostics?after={max([e['sequence'] for e in d1['events']] + [last])}")
            refused = [e for e in d2.get("events", []) if e["kind"] == "tls-refused"]
            record("a device from ANOTHER CA is refused, and diagnostics says why",
                   not ok and refused and "issuer" in refused[0]["detail"], refused[0]["detail"] if refused else str(d2)[:120])

            status, _, _ = hub.call("/api/download/ahu-7/../../ca/ca-key.pem")
            record("download with '..' refused", status in (400, 404))
            status, _, _ = hub.call("/api/download/ahu-7/cert1%2F..%2F..%2F..%2Fca%2Fca-key.pem")
            record("download with an encoded '..' refused", status in (400, 404))
            status, headers, rep = hub.call("/api/report")
            record("GET /api/report: a text report without keys",
                   status == 200 and b"diagnostic report" in rep and b"PRIVATE KEY" not in rep, f"{len(rep)} bytes")
            status, j = hub.json("/api/clients")
            record("GET /api/clients lists the device folders",
                   {c["label"] for c in j.get("clients", [])} >= {"client-01", "ahu-7", "tool-1"})
        finally:
            hub.stop()

        if lan:
            hub = Hub(exe, certs, tmp, http_bind=lan)
            try:
                hub.wait()
                status, j = hub.json("/api/sign", "POST", csr_pem(ec.generate_private_key(ec.SECP256R1()), "X"), password="")
                record(f"from a non-loopback address ({lan}) with no key password: signing refused (403)",
                       status == 403, j.get("error", ""))
                status, info = hub.json("/api/setup/info")
                record("  ... and /api/setup/info says why", info.get("gate", {}).get("allowedWithoutPassword") is False)
            finally:
                hub.stop()
        else:
            print("SKIP: no non-loopback address on this computer for the remote-access checks")

        # ======================= hub B: encrypted key ============================
        pw = "s3cret-Pässword"
        key_path = cert_paths.hub_private_key(certs)
        hub_key = serialization.load_pem_private_key(key_path.read_bytes(), None)
        key_path.write_bytes(hub_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.BestAvailableEncryption(pw.encode())))
        conf = tmp / "hub-b.conf"
        conf.write_text(f"sc-key-password = {pw}\n", encoding="utf-8")
        hub = Hub(exe, certs, tmp, "--config", str(conf))
        try:
            record("hub B (encrypted key, sc-key-password) starts", hub.wait())
            status, info = hub.json("/api/setup/info")
            record("  the gate says a password is needed", info.get("gate", {}).get("passwordProtectedKey") is True)
            body = csr_pem(ec.generate_private_key(ec.SECP256R1()), "B1")
            status, j = hub.json("/api/sign?label=b1", "POST", body, password="")
            record("  no password -> 401", status == 401, j.get("error", ""))
            status, j = hub.json("/api/sign?label=b1", "POST", body, password="wrong")
            record("  wrong password -> 401", status == 401, j.get("error", ""))
            status, j = hub.json("/api/sign?label=b1", "POST", body, password=pw)
            record("  right password (non-ASCII too) -> 200", status == 200 and j.get("ok"), j.get("error", ""))
            status, j = hub.json("/api/check-password", "POST", b"", password=pw)
            record("  /api/check-password with the right one -> 200", status == 200)
            status, _, _ = hub.call("/api/download/client-01/client-01.pfx", password="")
            status2, _, data = hub.call("/api/download/client-01/client-01.pfx", password=pw)
            record("  a private download needs the password (401 without, 200 with)", status == 401 and status2 == 200 and data)
            status, _, _ = hub.call("/api/download/client-01/bacnetsc.config")
            record("  a public download doesn't", status == 200)
            codes = [hub.json("/api/check-password", "POST", b"", password=f"bad{i}")[0] for i in range(6)]
            record("  after 5 wrong passwords a minute -> 429", codes[:3] == [401, 401, 401] and codes[-1] == 429, str(codes))
            status, _ = hub.json("/api/check-password", "POST", b"", password=pw)
            record("  ... even the right one, until the minute is up", status == 429)
            record("  every refusal is in the hub's log", hub.output().count("setup guide: REFUSED") >= 6)
        finally:
            hub.stop()

        if lan:
            hub = Hub(exe, certs, tmp, "--config", str(conf), http_bind=lan)
            try:
                hub.wait()
                status, j = hub.json("/api/sign", "POST", csr_pem(ec.generate_private_key(ec.SECP256R1()), "Y"), password=pw)
                record("hub B over plain HTTP from another address: refused even with the password (403)",
                       status == 403 and "plain HTTP" in j.get("error", ""), j.get("error", ""))
            finally:
                hub.stop()

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
