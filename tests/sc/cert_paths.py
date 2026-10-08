# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""Locate this example's certificate files for the tests/sc scripts.

The certificate folder is a CARI tree (ANSI/ASHRAE 135-2024 Annex AA.2; see
cert_layout.h), as tools/make_test_certs.py writes it and as the demo set in
certs/ is:

    <cert-dir>/cert1/device-<n>/port-<id>/hub/          marks the hub's own port folder
    <cert-dir>/cert1/device-<n>/port-<id>/opr-hub.pem   the hub's certificate
    <cert-dir>/cert1/device-<n>/port-<id>/key-hub.pem   the hub's private key
    <cert-dir>/cert1/device-<n>/port-<id>/csr-hub.pem   the hub's CSR
    <cert-dir>/cert1/issuer/iss-1.pem, iss-2.pem        the issuer(s)
    <cert-dir>/ca/ca-cert.pem, ca/ca-key.pem            the test CA
    <cert-dir>/clients/<label>-cari.zip: cert1/device-<n>/port-<id>/opr-<label>.pem, key-<label>.pem
    (client_files() unpacks them into <cert-dir>/.test-extract/<label>/)
"""
from pathlib import Path

DEFAULT_HUB_PORT_FOLDER = "cert1/device-389022/port-2"


def hub_port_folder(cert_dir: Path) -> Path:
    """The hub's CARI port folder (the one holding hub/)."""
    cert1 = Path(cert_dir) / "cert1"
    for device in sorted(cert1.glob("device-*")):
        for port in sorted(device.glob("port-*")):
            if (port / "hub").is_dir():
                return port
    return Path(cert_dir) / DEFAULT_HUB_PORT_FOLDER


def hub_certificate(cert_dir: Path) -> Path:
    return hub_port_folder(cert_dir) / "opr-hub.pem"


def hub_private_key(cert_dir: Path) -> Path:
    return hub_port_folder(cert_dir) / "key-hub.pem"


def hub_csr(cert_dir: Path) -> Path:
    return hub_port_folder(cert_dir) / "csr-hub.pem"


def issuer_certificate(cert_dir: Path) -> Path:
    return Path(cert_dir) / "cert1" / "issuer" / "iss-1.pem"


def issuer_certificate_2(cert_dir: Path) -> Path:
    return Path(cert_dir) / "cert1" / "issuer" / "iss-2.pem"


def pending_private_key(cert_dir: Path) -> Path:
    return Path(cert_dir) / "key-hub-pending.pem"


def ca_files(cert_dir: Path):
    """(CA certificate, CA private key)."""
    return Path(cert_dir) / "ca" / "ca-cert.pem", Path(cert_dir) / "ca" / "ca-key.pem"


def client_zip(cert_dir: Path, label: str) -> Path:
    """clients/<label>-cari.zip - a device's files, as one CARI response."""
    return Path(cert_dir) / "clients" / f"{label}-cari.zip"


def client_files(cert_dir: Path, label: str):
    """(certificate, private key) for a device label. Its clients/<label>-cari.zip
    is unpacked into <cert-dir>/.test-extract/<label>/ so TLS libraries can load
    the files."""
    import zipfile
    out = Path(cert_dir) / ".test-extract" / label
    with zipfile.ZipFile(client_zip(cert_dir, label)) as z:
        names = z.namelist()
        opr = [n for n in names if n.rsplit("/", 1)[-1].startswith("opr-")]
        key = [n for n in names if n.rsplit("/", 1)[-1].startswith("key-")]
        out.mkdir(parents=True, exist_ok=True)
        (out / "opr.pem").write_bytes(z.read(opr[0]))
        (out / "key.pem").write_bytes(z.read(key[0]))
    return out / "opr.pem", out / "key.pem"


def default_client_label(cert_dir: Path) -> str:
    """client-01, the first device tools/make_test_certs.py makes."""
    return "client-01"
