"""Locate this example's certificate files for the tests/sc scripts.

`BACnetExampleBSCHUB --generate-certs` writes a CARI tree (ANSI/ASHRAE 135-2024
Annex AA.2; see cert_layout.h). Earlier releases wrote flat names
(operational-certificate.pem, ...) or the older hub.crt / ca.crt / node.crt.
The hub reads all three, so the tests do too, with the same rules as
CertLayout::ResolveHubCertPaths:

    CARI (this release)
    <cert-dir>/cert1/device-<n>/port-<id>/hub/          marks the hub's own port folder
    <cert-dir>/cert1/device-<n>/port-<id>/opr-hub.pem   the hub's certificate
    <cert-dir>/cert1/device-<n>/port-<id>/key-hub.pem   the hub's private key
    <cert-dir>/cert1/device-<n>/port-<id>/csr-hub.pem   the hub's CSR
    <cert-dir>/cert1/issuer/iss-1.pem, iss-2.pem        the issuer(s)
    <cert-dir>/ca/ca-cert.pem, ca/ca-key.pem            the lab CA
    <cert-dir>/clients/<label>/cert1/device-<n>/port-<id>/opr-<label>.pem, key-<label>.pem

    flat (1.4) / older: operational-certificate.pem (hub.crt), private-key.pem (hub.key),
    certificate-signing-request.pem (hub.csr), issuer-certificate.pem (ca.crt),
    issuer-certificate-2.pem; clients/<label>/operational-certificate.pem, or <label>.crt
"""
from pathlib import Path


def _resolve(cert_dir: Path, name: str, legacy: str) -> Path:
    if (cert_dir / name).is_file() or not (cert_dir / legacy).is_file():
        return cert_dir / name
    return cert_dir / legacy


def hub_port_folder(cert_dir: Path):
    """The hub's CARI port folder (the one holding hub/), or None for an older layout."""
    cert1 = Path(cert_dir) / "cert1"
    if not cert1.is_dir():
        return None
    for device in sorted(cert1.glob("device-*")):
        for port in sorted(device.glob("port-*")):
            if (port / "hub").is_dir():
                return port
    return None


def hub_certificate(cert_dir: Path) -> Path:
    port = hub_port_folder(cert_dir)
    return port / "opr-hub.pem" if port else _resolve(cert_dir, "operational-certificate.pem", "hub.crt")


def hub_private_key(cert_dir: Path) -> Path:
    port = hub_port_folder(cert_dir)
    return port / "key-hub.pem" if port else _resolve(cert_dir, "private-key.pem", "hub.key")


def hub_csr(cert_dir: Path) -> Path:
    port = hub_port_folder(cert_dir)
    return port / "csr-hub.pem" if port else _resolve(cert_dir, "certificate-signing-request.pem", "hub.csr")


def issuer_certificate(cert_dir: Path) -> Path:
    if (Path(cert_dir) / "cert1").is_dir():
        return Path(cert_dir) / "cert1" / "issuer" / "iss-1.pem"
    return _resolve(cert_dir, "issuer-certificate.pem", "ca.crt")


def issuer_certificate_2(cert_dir: Path) -> Path:
    if (Path(cert_dir) / "cert1").is_dir():
        return Path(cert_dir) / "cert1" / "issuer" / "iss-2.pem"
    return Path(cert_dir) / "issuer-certificate-2.pem"


def pending_private_key(cert_dir: Path) -> Path:
    if (Path(cert_dir) / "cert1").is_dir():
        return Path(cert_dir) / "key-hub-pending.pem"
    return Path(cert_dir) / "private-key-pending.pem"


def ca_files(cert_dir: Path):
    """(CA certificate, CA private key)."""
    if (Path(cert_dir) / "ca").is_dir():
        return Path(cert_dir) / "ca" / "ca-cert.pem", Path(cert_dir) / "ca" / "ca-key.pem"
    return issuer_certificate(cert_dir), _resolve(cert_dir, "issuer-private-key.pem", "ca.key")


def client_files(cert_dir: Path, label: str):
    """(certificate, private key) for a client label, any naming."""
    folder = Path(cert_dir) / "clients" / label
    oprs = sorted(folder.glob(f"cert1/device-*/port-*/opr-{label}.pem")) or sorted(folder.glob("cert1/device-*/port-*/opr-*.pem"))
    if oprs:
        name = oprs[0].name[len("opr-"):]
        return oprs[0], oprs[0].parent / ("key-" + name)
    if (folder / "operational-certificate.pem").is_file():
        return folder / "operational-certificate.pem", folder / "private-key.pem"
    return Path(cert_dir) / f"{label}.crt", Path(cert_dir) / f"{label}.key"


def default_client_label(cert_dir: Path) -> str:
    """node (older certificate folders) if present, else client-01 (--generate-certs)."""
    return "node" if (Path(cert_dir) / "node.crt").is_file() else "client-01"
