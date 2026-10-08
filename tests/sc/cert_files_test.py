#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""
Checks what tools/make_test_certs.py writes for each device: ONE file,
clients/<label>-cari.zip, and nothing else.

  - it is a valid CARI response (ANSI/ASHRAE 135-2024 Annex AA.2): only CARI
    names - cert1/device-<n>/port-<id>/{csr,opr,key}-<label>.pem,
    cert1/issuer/iss-1.pem and cert1/response-notes.txt, folders included;
  - opr-<label>.pem is signed by iss-1.pem, for key-<label>.pem, from
    csr-<label>.pem;
  - response-notes.txt is the readme: it names each file, says which is
    private, and gives the hub URI;
  - there is no other file for the device in clients/ (no folder, no
    bacnetsc.config, no .pfx).

    python tools/make_test_certs.py --cert-dir certs --devices 1
    python tests/sc/cert_files_test.py --cert-dir certs

Exit code 0 = every check passed.
"""
import argparse
import re
import sys
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key

RESULTS = []
CARI_NAME = re.compile(r"^cert1/(device-\d+/(port-[^/<>:\"\\|?*]+/((csr|opr|key)-[^/<>:\"\\|?*]+\.pem)?)?|"
                       r"issuer/(iss-[12]\.pem)?|response-notes\.txt)?$")


def record(name, ok, detail=""):
    ok = bool(ok)
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def spki(key):
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cert-dir", default="certs")
    args = parser.parse_args()
    clients = Path(args.cert_dir) / "clients"
    zips = sorted(clients.glob("*-cari.zip"))
    record("at least one device zip", bool(zips), str(len(zips)))
    others = [p.name for p in clients.iterdir() if not p.name.endswith("-cari.zip")]
    record("clients/ holds only <label>-cari.zip files", not others, ", ".join(others))
    for path in zips:
        label = path.name[:-len("-cari.zip")]
        with zipfile.ZipFile(path) as z:
            record(f"{label}: zip CRCs", z.testzip() is None)
            names = z.namelist()
            files = {n: z.read(n) for n in names if not n.endswith("/")}
        bad = [n for n in names if not CARI_NAME.match(n)]
        record(f"{label}: only CARI names in the zip", not bad, ", ".join(bad))
        opr = [n for n in files if n.endswith(f"/opr-{label}.pem")]
        key = [n for n in files if n.endswith(f"/key-{label}.pem")]
        csr = [n for n in files if n.endswith(f"/csr-{label}.pem")]
        record(f"{label}: opr-, key-, csr-<label>.pem in one port folder",
               len(opr) == len(key) == len(csr) == 1 and opr[0].rsplit("/", 1)[0] == key[0].rsplit("/", 1)[0],
               ", ".join(opr + key + csr))
        if not (opr and key and csr):
            continue
        cert = x509.load_pem_x509_certificate(files[opr[0]])
        pkey = load_pem_private_key(files[key[0]], None)
        req = x509.load_pem_x509_csr(files[csr[0]])
        issuer = x509.load_pem_x509_certificate(files["cert1/issuer/iss-1.pem"])
        try:
            cert.verify_directly_issued_by(issuer)
            record(f"{label}: opr is signed by iss-1", True)
        except Exception as exc:  # noqa: BLE001
            record(f"{label}: opr is signed by iss-1", False, str(exc))
        record(f"{label}: opr is for key- and csr-", spki(cert.public_key()) == spki(pkey.public_key()) ==
               spki(req.public_key()))
        notes = files.get("cert1/response-notes.txt", b"").decode("utf-8", "replace")
        record(f"{label}: response-notes.txt is the readme (files, private, hub URI)",
               opr[0] in notes and key[0] in notes and "iss-1.pem" in notes and "PRIVATE" in notes and "wss://" in notes,
               f"{len(notes)} chars")
        record(f"{label}: response-notes.txt within CARI's 10 kB", len(files.get("cert1/response-notes.txt", b"")) <= 10240)

    passed = sum(RESULTS)
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
