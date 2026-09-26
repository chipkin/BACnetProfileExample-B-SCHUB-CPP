#!/usr/bin/env python3
"""
Checks the files --generate-certs writes in each clients/<label>/ folder for
Windows tools such as YABE (issue #38):

  - <label>.pfx loads with an EMPTY password (what YABE uses) and holds the
    folder's operational certificate, the matching private key and the issuer;
  - issuer-certificate.cer is issuer-certificate.pem in DER;
  - yabe-bacnetsc.config is valid XML naming the hub URI, the .pfx and the .cer.

    BACnetExampleBSCHUB --sc-cert-dir certs --generate-certs 1
    python tests/sc/cert_files_test.py --cert-dir certs

Exit code 0 = every check passed.
"""
import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs12

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cert-dir", default="certs")
    args = parser.parse_args()
    clients = sorted(p for p in (Path(args.cert_dir) / "clients").iterdir() if p.is_dir())
    record("at least one client folder", bool(clients), str(len(clients)))
    for folder in clients:
        label = folder.name
        cert = x509.load_pem_x509_certificate((folder / "operational-certificate.pem").read_bytes())
        key = load_pem_private_key((folder / "private-key.pem").read_bytes(), None)
        issuer = x509.load_pem_x509_certificate((folder / "issuer-certificate.pem").read_bytes())

        try:
            pfx_key, pfx_cert, pfx_chain = pkcs12.load_key_and_certificates((folder / f"{label}.pfx").read_bytes(), b"")
            record(f"{label}: .pfx certificate", pfx_cert == cert)
            record(f"{label}: .pfx private key matches private-key.pem",
                   pfx_key.public_key().public_numbers() == key.public_key().public_numbers())
            record(f"{label}: .pfx chain is the issuer", pfx_chain == [issuer])
        except Exception as exc:  # noqa: BLE001 - report any load failure as a test failure
            record(f"{label}: .pfx loads with an empty password", False, f"{type(exc).__name__}: {exc}")

        der = x509.load_der_x509_certificate((folder / "issuer-certificate.cer").read_bytes())
        record(f"{label}: issuer-certificate.cer is the issuer in DER", der == issuer)

        root = ET.parse(folder / "yabe-bacnetsc.config").getroot()
        own = Path(root.findtext("OwnCertificateFile", ""))
        hub = Path(root.findtext("HubCertificateFile", ""))
        record(f"{label}: yabe-bacnetsc.config names the hub URI",
               root.findtext("primaryHubURI", "").startswith("wss://"), root.findtext("primaryHubURI"))
        record(f"{label}: yabe-bacnetsc.config points at the .pfx and .cer",
               own.name == f"{label}.pfx" and own.is_absolute() and hub.name == "issuer-certificate.cer" and hub.is_absolute(),
               f"{own} / {hub}")

    passed = sum(RESULTS)
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
