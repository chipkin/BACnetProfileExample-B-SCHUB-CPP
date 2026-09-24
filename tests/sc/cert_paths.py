"""Locate this example's certificate files for the tests/sc scripts.

`BACnetExampleBSCHUB --generate-certs` writes PEM files named after the BACnet
Network Port properties (see cert_tool.h); scripts/generate-test-certs.cmake
writes the older names. The hub reads either, so the tests do too - the
BACnet name wins when both exist, the same rule as CertTool::ResolveCertFile.

    <cert-dir>/operational-certificate.pem   (or hub.crt)   the hub's certificate
    <cert-dir>/private-key.pem               (or hub.key)   the hub's private key
    <cert-dir>/issuer-certificate.pem        (or ca.crt)    the issuer (CA)
    <cert-dir>/clients/<label>/operational-certificate.pem  a client's certificate
    <cert-dir>/clients/<label>/private-key.pem              a client's private key
    <cert-dir>/<label>.crt / <label>.key                     older client naming (node.crt)
"""
from pathlib import Path


def _resolve(cert_dir: Path, name: str, legacy: str) -> Path:
    if (cert_dir / name).is_file() or not (cert_dir / legacy).is_file():
        return cert_dir / name
    return cert_dir / legacy


def hub_certificate(cert_dir: Path) -> Path:
    return _resolve(cert_dir, "operational-certificate.pem", "hub.crt")


def hub_private_key(cert_dir: Path) -> Path:
    return _resolve(cert_dir, "private-key.pem", "hub.key")


def issuer_certificate(cert_dir: Path) -> Path:
    return _resolve(cert_dir, "issuer-certificate.pem", "ca.crt")


def client_files(cert_dir: Path, label: str):
    """(certificate, private key) for a client label, either naming."""
    folder = cert_dir / "clients" / label
    if (folder / "operational-certificate.pem").is_file():
        return folder / "operational-certificate.pem", folder / "private-key.pem"
    return cert_dir / f"{label}.crt", cert_dir / f"{label}.key"


def default_client_label(cert_dir: Path) -> str:
    """node (scripts/generate-test-certs.cmake) if present, else client-01 (--generate-certs)."""
    return "node" if (cert_dir / "node.crt").is_file() else "client-01"
