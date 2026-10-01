#!/usr/bin/env python3
"""
Checks the files --generate-certs writes in each clients/<label>/ folder:

  - the folder's cert1/ is a CARI response (ANSI/ASHRAE 135-2024 Annex AA.2):
    cert1/device-<n>/port-<id>/{csr,opr,key}-<label>.pem and cert1/issuer/iss-1.pem,
    and <label>-cari-response.zip holds exactly that tree (empty folders included);
  - opr-<label>.pem is signed by iss-1.pem, for key-<label>.pem, from csr-<label>.pem;
  - bacnetsc.config names the hub URI and those files by relative path;
  - for Windows tools such as YABE (issue #38): <label>.pfx loads with an EMPTY
    password and holds the certificate, the matching key and the issuer;
    iss-1.cer is iss-1.pem in DER; yabe-bacnetsc.config names the .pfx and .cer.

    BACnetExampleBSCHUB --sc-cert-dir certs --generate-certs 1
    python tests/sc/cert_files_test.py --cert-dir certs

Exit code 0 = every check passed.
"""
import argparse
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key, pkcs12

import cert_paths

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def spki(key):
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cert-dir", default="certs")
    args = parser.parse_args()
    cert_dir = Path(args.cert_dir)
    clients = sorted(p for p in (cert_dir / "clients").iterdir() if p.is_dir())
    record("at least one client folder", bool(clients), str(len(clients)))
    for folder in clients:
        label = folder.name
        opr_path, key_path = cert_paths.client_files(cert_dir, label)
        record(f"{label}: CARI opr-/key- files", opr_path.is_file() and key_path.is_file(),
               str(opr_path.relative_to(folder)))
        port = opr_path.parent
        csr_path = port / f"csr-{label}.pem"
        cert = x509.load_pem_x509_certificate(opr_path.read_bytes())
        key = load_pem_private_key(key_path.read_bytes(), None)
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        issuer = x509.load_pem_x509_certificate((folder / "cert1" / "issuer" / "iss-1.pem").read_bytes())
        try:
            cert.verify_directly_issued_by(issuer)
            record(f"{label}: opr is signed by iss-1", True)
        except Exception as exc:  # noqa: BLE001
            record(f"{label}: opr is signed by iss-1", False, str(exc))
        record(f"{label}: opr is for key- and csr-", spki(cert.public_key()) == spki(key.public_key()) ==
               spki(csr.public_key()))

        # The zip is the cert1/ tree, folders and all.
        on_disk = {p.relative_to(folder).as_posix() + ("/" if p.is_dir() else "") for p in (folder / "cert1").rglob("*")}
        on_disk.add("cert1/")
        with zipfile.ZipFile(folder / f"{label}-cari-response.zip") as z:
            record(f"{label}: zip CRCs", z.testzip() is None)
            in_zip = set(z.namelist())
            same_bytes = all(z.read(n) == (folder / n).read_bytes() for n in in_zip if not n.endswith("/"))
        record(f"{label}: <label>-cari-response.zip is the cert1/ tree", in_zip == on_disk and same_bytes,
               ", ".join(sorted(in_zip ^ on_disk)))

        root = ET.parse(folder / "bacnetsc.config").getroot()
        record(f"{label}: bacnetsc.config names the CARI files",
               (folder / root.findtext("operationalCertificate", "")).resolve() == opr_path.resolve() and
               (folder / root.findtext("devicePrivateKeyFile", "")).resolve() == key_path.resolve() and
               root.findtext("issuerCertificate") == "cert1/issuer/iss-1.pem",
               root.findtext("operationalCertificate"))

        try:
            pfx_key, pfx_cert, pfx_chain = pkcs12.load_key_and_certificates((folder / f"{label}.pfx").read_bytes(), b"")
            record(f"{label}: .pfx certificate", pfx_cert == cert)
            record(f"{label}: .pfx private key matches key-{label}.pem", spki(pfx_key.public_key()) == spki(key.public_key()))
            record(f"{label}: .pfx chain is the issuer", pfx_chain == [issuer])
        except Exception as exc:  # noqa: BLE001 - report any load failure as a test failure
            record(f"{label}: .pfx loads with an empty password", False, f"{type(exc).__name__}: {exc}")

        der = x509.load_der_x509_certificate((folder / "iss-1.cer").read_bytes())
        record(f"{label}: iss-1.cer is the issuer in DER", der == issuer)

        root = ET.parse(folder / "yabe-bacnetsc.config").getroot()
        own = Path(root.findtext("OwnCertificateFile", ""))
        hub = Path(root.findtext("HubCertificateFile", ""))
        record(f"{label}: yabe-bacnetsc.config names the hub URI",
               root.findtext("primaryHubURI", "").startswith("wss://"), root.findtext("primaryHubURI"))
        record(f"{label}: yabe-bacnetsc.config points at the .pfx and .cer",
               own.name == f"{label}.pfx" and own.is_absolute() and hub.name == "iss-1.cer" and hub.is_absolute(),
               f"{own} / {hub}")

    passed = sum(RESULTS)
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
