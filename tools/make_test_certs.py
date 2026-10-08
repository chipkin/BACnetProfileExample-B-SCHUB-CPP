#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../LICENSE.
"""Make a set of TEST certificates for the B-SCHUB example hub (BACnetExampleBSCHUB).

FOR TESTING ONLY. The certificate authority (CA) made here is throwaway and
none of the private keys are protected. Real certificates come from a
Certificate Authority: the Chipkin BACnet SC Certificate Authority, BACnet
International's BACCARI, or your own CARI-compatible CA.

The demo set in the repository's certs/ folder was made with this script:
    python tools/make_test_certs.py --cert-dir certs --hub-uri wss://127.0.0.1:4443/ --portable

The files are laid out in the CARI format (ANSI/ASHRAE 135-2024 Annex AA.2),
the same tree the hub reads from --sc-cert-dir:

    ca/ca-cert.pem, ca/ca-key.pem                  the test CA (not CARI)
    cert1/device-<hub>/port-2/hub/                 marks the hub's own port
    cert1/device-<hub>/port-2/opr-hub.pem          the hub's certificate
    cert1/device-<hub>/port-2/key-hub.pem          its private key
    cert1/device-<hub>/port-2/csr-hub.pem          its signing request
    cert1/issuer/iss-1.pem                         the CA certificate
    clients/<label>-cari.zip                       one CARI response per device
    certificates.txt, readme.txt

Certificates: ECDSA P-256 with SHA-256. The CA is valid 10 years, the others
825 days. The hub's certificate is for serverAuth and clientAuth, with the
names localhost, 127.0.0.1, this computer's host name (left out with
--portable) and the hub URI's host. Device certificates are for clientAuth.

Usage:

    python tools/make_test_certs.py                       # ./certs, 3 devices
    python tools/make_test_certs.py --cert-dir certs --devices 1
    python tools/make_test_certs.py --cert-dir certs --force
    python tools/make_test_certs.py --cert-dir certs --add-devices 2
    python tools/make_test_certs.py --hub-uri wss://hub.example.local:4443/

Then start the hub with:  BACnetExampleBSCHUB --sc-cert-dir certs

Needs the "cryptography" package (pip install cryptography).
"""
import argparse
import datetime
import os
import re
import secrets
import shutil
import socket
import stat
import sys
import time
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# --- what the hub uses (main.cpp, cert_layout.h, cert_tool.h) ------------------
DEFAULT_HUB_DEVICE_INSTANCE = 389022
DEFAULT_SC_PORT = 4443
HUB_PORT_ID = "2"
HUB_FILE_NAME = "hub"
ISSUER_LABEL = "issuer"
DEFAULT_DEVICE_COUNT = 3
DEFAULT_LABEL_PREFIX = "client"
DEFAULT_DEVICE_PORT_ID = "1"
CLIENTS_DIR = "clients"
CLIENT_ZIP_SUFFIX = "-cari.zip"
MAX_NOTES = 10 * 1024

# --- certificate profile -------------------------------------------------------
CA_VALID_DAYS = 3650
LEAF_VALID_DAYS = 825
ORGANIZATION = "Chipkin Automation Systems (demo, not for production)"
CN_PREFIX = "Chipkin Example B-SCHUB demo "  # + label
CA_COMMON_NAME = CN_PREFIX + "CA"            # + a random suffix
TOOL = "make_test_certs.py"

# Every file name outside cert1/ and ca/ a certificate set may own.
SET_FILES = [
    "key-hub-pending.pem", "trusted-issuers.pem", "issuer-crl.pem", "certificates.txt", "readme.txt",
    "hub-cari-request.zip",
]
OWNED_FOLDERS = ["cert1", "ca"]


class CertError(Exception):
    pass


# --- paths -------------------------------------------------------------------------

class HubPaths:
    """The files of a certificate set (mirrors CertLayout::HubCertPaths)."""

    def __init__(self, cert_dir: Path, port_folder: str):
        self.cert_dir = cert_dir
        self.port_folder = port_folder  # "cert1/device-389022/port-2"
        port = cert_dir / port_folder
        self.operational_certificate = port / f"opr-{HUB_FILE_NAME}.pem"
        self.certificate_signing_request = port / f"csr-{HUB_FILE_NAME}.pem"
        self.private_key = port / f"key-{HUB_FILE_NAME}.pem"
        self.issuer_certificate_1 = cert_dir / "cert1" / "issuer" / "iss-1.pem"
        self.issuer_certificate_2 = cert_dir / "cert1" / "issuer" / "iss-2.pem"
        self.ca_certificate = cert_dir / "ca" / "ca-cert.pem"
        self.ca_private_key = cert_dir / "ca" / "ca-key.pem"
        self.manifest = cert_dir / "certificates.txt"
        self.readme = cert_dir / "readme.txt"
        self.clients_dir = cert_dir / CLIENTS_DIR


def cari_paths(cert_dir: Path, hub_device_instance: int) -> HubPaths:
    return HubPaths(cert_dir, f"cert1/device-{hub_device_instance}/port-{HUB_PORT_ID}")


def resolve_paths(cert_dir: Path, hub_device_instance: int) -> HubPaths:
    """An existing set: the CARI port folder holding hub/ (preferring the given
    instance) - mirrors CertLayout::ResolveHubCertPaths."""
    cert1 = cert_dir / "cert1"
    if cert1.is_dir():
        found = []
        for device in sorted(cert1.iterdir()):
            m = re.fullmatch(r"device-(\d{1,7})", device.name)
            if not device.is_dir() or not m or int(m.group(1)) > 4194302:
                continue
            for port in sorted(device.iterdir()):
                if port.is_dir() and port.name.startswith("port-") and (port / "hub").is_dir():
                    found.append((f"cert1/{device.name}/{port.name}", int(m.group(1))))
        if not found:
            return cari_paths(cert_dir, hub_device_instance)
        chosen = next((f for f in found if f[1] == hub_device_instance), found[0])
        return HubPaths(cert_dir, chosen[0])
    return cari_paths(cert_dir, hub_device_instance)


# --- files ---------------------------------------------------------------------------

def write_file(path: Path, data: bytes, is_private: bool = False) -> None:
    """Writes `data`; a private file gets owner read/write only where the OS
    allows it (on Windows the folder's ACL is what protects it)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if is_private:
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def csr_pem(csr) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)


# --- certificates ---------------------------------------------------------------------

def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def lab_subject(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
                      x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def primary_ipv4() -> str:
    """This computer's LAN address (the interface with the default route), or
    127.0.0.1. Connecting a UDP socket sends nothing."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def local_hostname() -> str:
    return socket.gethostname() or "localhost"


def hub_subject_alt_name(hub_uri: str, portable: bool = False) -> x509.SubjectAlternativeName:
    """localhost, 127.0.0.1, this computer's host name (unless `portable`) and
    the hub URI's host (an IPv6 [literal] is left out), without duplicates."""
    import ipaddress
    entries = [("DNS", "localhost"), ("IP", "127.0.0.1")]
    if not portable:
        entries.append(("DNS", local_hostname()))
    host = hub_uri.split("://", 1)[1] if "://" in hub_uri else hub_uri
    host = re.split(r"[:/]", host, maxsplit=1)[0]
    if host and not host.startswith("["):
        entries.append(("IP" if re.fullmatch(r"[0-9.]+", host) else "DNS", host))
    names, seen = [], set()
    for kind, value in entries:
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(value)) if kind == "IP" else x509.DNSName(value))
        except ValueError:
            names.append(x509.DNSName(value))
    return x509.SubjectAlternativeName(names)


def make_certificate(role: str, subject: x509.Name, public_key, issuer=None, hub_uri: str = "", self_key=None,
                     portable: bool = False):
    """role: "ca" (self-signed with self_key), "hub" or "client". issuer: (cert, key) that signs it."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    days = CA_VALID_DAYS if role == "ca" else LEAF_VALID_DAYS
    serial = int.from_bytes(secrets.token_bytes(16), "big") & ((1 << 127) - 1)  # positive, up to 127 bits
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer[0].subject if issuer else subject)
               .public_key(public_key)
               .serial_number(serial or 1)
               # Valid from an hour ago, so a device whose clock is a little
               # behind doesn't reject a fresh certificate as "not yet valid".
               .not_valid_before(now - datetime.timedelta(hours=1))
               .not_valid_after(now + datetime.timedelta(days=days)))
    if role == "ca":
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
    else:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
            critical=False)
        issuer_ski = issuer[0].extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski), critical=False)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    if role == "hub":
        # TLS server and client: a BACnet/SC certificate is presented at both
        # ends of a connection.
        builder = builder.add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        builder = builder.add_extension(hub_subject_alt_name(hub_uri, portable), critical=False)
    elif role == "client":
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    signing_key = issuer[1] if issuer else self_key
    return builder.sign(signing_key, hashes.SHA256())


def make_csr(key, subject: x509.Name):
    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())


def serial_hex(cert) -> str:
    n = cert.serial_number
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big").hex().upper()


def fingerprint(cert) -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def not_after(cert) -> str:
    return cert.not_valid_after_utc.strftime("%Y-%m-%d")


def record(paths: HubPaths, label: str, role: str, where: str, cert) -> None:
    """One line in certificates.txt (with a header the first time), echoed."""
    is_new = not paths.manifest.exists()
    with open(paths.manifest, "ab") as f:
        if is_new:
            f.write(f"# Test BACnet/SC certificates generated by {TOOL} (TESTING ONLY).\n"
                    "# label | role | location | serial | expires | SHA-256 fingerprint\n".encode())
        f.write(f"{label} | {role} | {where or './'} | {serial_hex(cert)} | {not_after(cert)} | "
                f"{fingerprint(cert)}\n".encode())
    print(f"  {label:<14} {role:<7} {where or './'}  (expires {not_after(cert)})")


# --- the CA ---------------------------------------------------------------------------

def load_ca(paths: HubPaths):
    """The CA in ca/. It must be one of the hub's issuers,
    or the hub would refuse every device it signs."""
    if not paths.ca_certificate.exists() or not paths.ca_private_key.exists():
        raise CertError(f'no CA to sign with: "{paths.ca_certificate}" and "{paths.ca_private_key}" are needed '
                        "(make a set first, without --add-devices)")
    try:
        cert = x509.load_pem_x509_certificate(paths.ca_certificate.read_bytes())
    except ValueError:
        raise CertError(f'"{paths.ca_certificate}" is not a PEM certificate')
    try:
        key = serialization.load_pem_private_key(paths.ca_private_key.read_bytes(), None)
    except (ValueError, TypeError):
        raise CertError(f'"{paths.ca_private_key}" is not an unencrypted PEM private key')
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(serialization.Encoding.DER, spki) != \
            cert.public_key().public_bytes(serialization.Encoding.DER, spki):
        raise CertError(f'"{paths.ca_private_key}" is not the key of "{paths.ca_certificate}"')
    ca_der = cert.public_bytes(serialization.Encoding.DER)
    for issuer_path in (paths.issuer_certificate_1, paths.issuer_certificate_2):
        if issuer_path.exists():
            try:
                certs = x509.load_pem_x509_certificates(issuer_path.read_bytes())
            except ValueError:
                certs = []
            if any(c.public_bytes(serialization.Encoding.DER) == ca_der for c in certs):
                return cert, key
    raise CertError(f'the CA "{paths.ca_certificate}" is not one of the hub\'s issuer certificates '
                    f"({paths.issuer_certificate_1}, {paths.issuer_certificate_2})")


# --- device zips ----------------------------------------------------------------------

DEVICE_NOTES = """BACnet/SC device certificate "%LABEL%" - made by %TOOL% (TESTING ONLY)
%CANOTE%
This zip is a CARI response (ANSI/ASHRAE 135-2024 Annex AA.2) for ONE device:

  %OPR%
      PUBLIC   The device's operational certificate -> its Operational_Certificate_File.
               Subject: %SUBJECT%
  %KEY%
      PRIVATE  This device's private key - keep it, and so this whole zip, private.
  %CSR%
      PUBLIC   The request the certificate was signed from.
  cert1/issuer/iss-1.pem
      PUBLIC   The CA that signed the hub's certificate -> the device's
               Issuer_Certificate_Files (load it into both slots if there are two).
  cert1/response-notes.txt
      This note.

To connect the device: install the operational certificate with its private
key, install iss-1.pem as its issuer certificate, and set its primary hub URI
to %HUBURI%
A tool that imports CARI files can take this zip as it is.
"""


def highest_client_number(clients_dir: Path, prefix: str) -> int:
    """Highest NN among clients/<prefix>-NN-cari.zip, -cari-request.zip and
    clients/<prefix>-NN/ folders. 0 if none."""
    pattern = re.compile("^" + re.escape(prefix) + r"-([0-9]+)(-cari\.zip|-cari-request\.zip)?$")
    highest = 0
    if not clients_dir.is_dir():
        return 0
    for entry in clients_dir.iterdir():
        m = pattern.match(entry.name)
        if m and entry.is_dir() == (m.group(2) is None):
            n = int(m.group(1))
            if n <= 99999:
                highest = max(highest, n)
    return highest


def label_number(label: str) -> int:
    tail = label.rsplit("-", 1)
    return int(tail[1]) if len(tail) == 2 and tail[1].isdigit() else 0


def is_valid_label(label: str) -> bool:
    return (0 < len(label) <= 64 and label not in (HUB_FILE_NAME, ISSUER_LABEL)
            and re.fullmatch(r"[A-Za-z0-9_.-]+", label) is not None)


def write_zip(path: Path, files: dict) -> None:
    """A CARI zip: every folder (as its own entry, so empty ones survive), then
    every file, each in path order - as cari.cpp's WriteZip writes it."""
    folders = set()
    for name in files:
        parts = name.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            folders.add("/".join(parts[:i]))
    stamp = time.localtime()[:6]
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        for folder in sorted(folders):
            info = zipfile.ZipInfo(folder + "/", stamp)
            info.create_system = 0
            info.external_attr = 0x10  # MS-DOS directory bit
            info.compress_type = zipfile.ZIP_STORED
            z.writestr(info, b"")
        for name in sorted(files):
            info = zipfile.ZipInfo(name, stamp)
            info.create_system = 0
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, files[name])


def issue_device_zip(paths: HubPaths, ca, label: str, device_instance: int, port_id: str, hub_uri: str) -> None:
    """A device's key, CSR and certificate as clients/<label>-cari.zip."""
    zip_path = paths.clients_dir / (label + CLIENT_ZIP_SUFFIX)
    if zip_path.exists() or (paths.clients_dir / label).exists():
        raise CertError(f"clients/{label}{CLIENT_ZIP_SUFFIX} (or a clients/{label}/ folder) already exists")
    key = new_key()
    subject = lab_subject(CN_PREFIX + label)
    csr = make_csr(key, subject)
    cert = make_certificate("client", csr.subject, csr.public_key(), issuer=ca)
    port = f"cert1/device-{device_instance}/port-{port_id}"
    files = {
        f"{port}/csr-{label}.pem": csr_pem(csr),
        f"{port}/key-{label}.pem": key_pem(key),
        f"{port}/opr-{label}.pem": cert_pem(cert),
        "cert1/issuer/iss-1.pem": paths.issuer_certificate_1.read_bytes(),
    }
    if paths.issuer_certificate_2.exists():
        second = paths.issuer_certificate_2.read_bytes()
        if second and second != files["cert1/issuer/iss-1.pem"]:
            files["cert1/issuer/iss-2.pem"] = second
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ca_note = (f"Processed by the {TOOL} test CA ({ca[0].subject.rfc4514_string()}) on {today}: "
               "1 signed, 0 refused.\n")
    notes = DEVICE_NOTES
    for token, value in (("%LABEL%", label), ("%TOOL%", TOOL), ("%CANOTE%", ca_note),
                         ("%OPR%", f"{port}/opr-{label}.pem"), ("%CSR%", f"{port}/csr-{label}.pem"),
                         ("%KEY%", f"{port}/key-{label}.pem"), ("%SUBJECT%", cert.subject.rfc4514_string()),
                         ("%HUBURI%", hub_uri)):
        notes = notes.replace(token, value)
    files["cert1/response-notes.txt"] = notes.encode("utf-8")[:MAX_NOTES]
    write_zip(zip_path, files)
    try:
        os.chmod(zip_path, stat.S_IRUSR | stat.S_IWUSR)  # it holds the private key
    except OSError:
        pass
    record(paths, label, "client", f"{CLIENTS_DIR}/{label}{CLIENT_ZIP_SUFFIX}", cert)


def issue_devices(paths: HubPaths, ca, count: int, prefix: str, first_instance, port_id: str, hub_uri: str):
    first = highest_client_number(paths.clients_dir, prefix) + 1
    for i in range(count):
        label = f"{prefix}-{first + i:02d}"
        if first_instance is not None:
            instance = first_instance + i
        else:
            instance = label_number(label) or 1
        issue_device_zip(paths, ca, label, instance, port_id, hub_uri)


# --- readme.txt -------------------------------------------------------------------------

README = """BACnet/SC TEST certificates - made by tools/make_test_certs.py
=============================================================

TESTING ONLY. These certificates come from a throwaway certificate authority
and none of the private keys are protected. Real certificates come from a
Certificate Authority: the Chipkin BACnet SC Certificate Authority, BACnet
International's BACCARI, or your own CARI-compatible CA.

The files are laid out in the CARI format (Certificate Authority
Requirements Interchange, ANSI/ASHRAE 135-2024 Annex AA.2), the layout the
hub reads from --sc-cert-dir.


THE HUB'S OWN FILES
-------------------

cert1/
  device-<instance>/port-2/                     Network Port 2 "BACnet SC"
    hub/                                        empty: this port is a hub function
    opr-hub.pem                        PUBLIC   File 1, Operational_Certificate_File: the
                                                hub's certificate (serverAuth + clientAuth;
                                                names localhost, 127.0.0.1, this computer).
    key-hub.pem                        PRIVATE  Its private key.
    csr-hub.pem                        PUBLIC   File 2, Certificate_Signing_Request_File.
  issuer/iss-1.pem                     PUBLIC   File 3, Issuer_Certificate_Files[1]: the CA
                                                that signed the hub and every device.

ca/ca-cert.pem                         PUBLIC   The test CA's certificate (= iss-1.pem).
ca/ca-key.pem                          PRIVATE  The test CA's key. Only make_test_certs.py
                                                --add-devices uses it; the hub never does.
certificates.txt                       PUBLIC   One line per certificate: label, location,
                                                serial, expiry, fingerprint.


ONE FILE PER DEVICE: clients/<label>-cari.zip
---------------------------------------------

  cert1/device-<n>/port-<id>/opr-<label>.pem    PUBLIC   The device's certificate (clientAuth).
  cert1/device-<n>/port-<id>/key-<label>.pem    PRIVATE  Its private key - so the zip is private.
  cert1/device-<n>/port-<id>/csr-<label>.pem    PUBLIC   The request it was signed from.
  cert1/issuer/iss-1.pem                        PUBLIC   The issuer, to validate the hub.
  cert1/response-notes.txt                      PUBLIC   What each file is and how to install it.


HOW TO USE THESE FILES
----------------------

1. Start the hub with this folder:   BACnetExampleBSCHUB --sc-cert-dir <this folder>
2. Give each device its own clients/<label>-cari.zip.
3. More devices, signed by the SAME CA (the running hub trusts them at once):
       python tools/make_test_certs.py --cert-dir <this folder> --add-devices 2
4. Starting over: add --force. It deletes this whole set, including clients/,
   and makes a new CA. Every device then needs new files.


KEY AND CERTIFICATE DETAILS
---------------------------

    Keys:          ECDSA P-256 (prime256v1), PEM (PKCS#8)
    Signatures:    SHA-256
    CA:            valid 10 years; CA:TRUE; keyCertSign, cRLSign
    Hub:           valid 825 days; EKU serverAuth + clientAuth
    Devices:       valid 825 days; EKU clientAuth
"""


# --- modes ------------------------------------------------------------------------------

def generate_set(cert_dir: Path, hub_device_instance: int, devices: int, prefix: str, first_instance,
                 port_id: str, hub_uri: str, force: bool, portable: bool) -> None:
    cert_dir.mkdir(parents=True, exist_ok=True)
    if not force:
        for name in SET_FILES:
            if (cert_dir / name).exists() and name not in ("certificates.txt", "readme.txt", "trusted-issuers.pem"):
                raise CertError(f'"{cert_dir / name}" already exists. Replacing the CA invalidates every certificate '
                                "already handed out. Use --add-devices to add devices to the existing set, or add "
                                "--force to start over.")
        for folder in OWNED_FOLDERS:
            if (cert_dir / folder).exists():
                raise CertError(f'"{cert_dir / folder}" already exists - this folder already has a certificate set. '
                                "Use --add-devices to add devices, or add --force to start over.")
    else:
        for name in SET_FILES:
            try:
                (cert_dir / name).unlink()
            except FileNotFoundError:
                pass
        for folder in OWNED_FOLDERS + [CLIENTS_DIR]:
            shutil.rmtree(cert_dir / folder, ignore_errors=True)

    paths = cari_paths(cert_dir, hub_device_instance)
    print(f'Generating TEST BACnet/SC certificates in "{cert_dir}" (CARI layout, TESTING ONLY):')

    # The CA. A random suffix gives every test CA its own subject name, so two
    # sets never have issuers that only differ by key identifier.
    ca_key = new_key()
    ca_subject = lab_subject(f"{CA_COMMON_NAME} {secrets.token_hex(4).upper()}")
    ca_cert = make_certificate("ca", ca_subject, ca_key.public_key(), self_key=ca_key)
    write_file(paths.ca_private_key, key_pem(ca_key), is_private=True)
    write_file(paths.ca_certificate, cert_pem(ca_cert))
    write_file(paths.issuer_certificate_1, cert_pem(ca_cert))
    record(paths, ISSUER_LABEL, "issuer", "cert1/issuer/iss-1.pem", ca_cert)
    ca = (ca_cert, ca_key)

    # The hub: key, certificate, CSR (same subject) and the hub/ marker.
    hub_key = new_key()
    hub_cert = make_certificate("hub", lab_subject(CN_PREFIX + HUB_FILE_NAME), hub_key.public_key(), issuer=ca,
                                hub_uri=hub_uri, portable=portable)
    hub_csr = make_csr(hub_key, hub_cert.subject)
    (cert_dir / paths.port_folder / "hub").mkdir(parents=True, exist_ok=True)
    write_file(paths.private_key, key_pem(hub_key), is_private=True)
    write_file(paths.operational_certificate, cert_pem(hub_cert))
    write_file(paths.certificate_signing_request, csr_pem(hub_csr))
    record(paths, HUB_FILE_NAME, "hub", paths.port_folder + "/", hub_cert)

    issue_devices(paths, ca, devices, prefix, first_instance, port_id, hub_uri)
    write_file(paths.readme, README.encode())
    print(f"Done. Give each device its own {CLIENTS_DIR}/<label>{CLIENT_ZIP_SUFFIX}. Devices dial {hub_uri}.\n"
          "Keep ca/ca-key.pem private: it is only needed to sign more devices.")


def add_devices(cert_dir: Path, hub_device_instance: int, devices: int, prefix: str, first_instance,
                port_id: str, hub_uri: str) -> None:
    paths = resolve_paths(cert_dir, hub_device_instance)
    ca = load_ca(paths)
    print(f'Adding {devices} device certificate(s) signed by the existing CA in "{cert_dir}":')
    issue_devices(paths, ca, devices, prefix, first_instance, port_id, hub_uri)
    write_file(paths.readme, README.encode())
    print("Done. A running hub already trusts these (same CA) - no restart needed.")


def positive(text: str) -> int:
    n = int(text)
    if n < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return n


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cert-dir", default="certs", help="where to write the set (default ./certs)")
    parser.add_argument("--devices", type=positive, default=DEFAULT_DEVICE_COUNT,
                        help=f"device zips in a new set (default {DEFAULT_DEVICE_COUNT})")
    parser.add_argument("--add-devices", type=positive, metavar="N",
                        help="add N more device zips, signed by the CA already in --cert-dir")
    parser.add_argument("--hub-device-instance", type=int, default=DEFAULT_HUB_DEVICE_INSTANCE,
                        help=f"the hub's device instance: cert1/device-<n>/port-2/ "
                             f"(default {DEFAULT_HUB_DEVICE_INSTANCE})")
    parser.add_argument("--hub-uri", help=f"the URI devices dial; its host goes in the hub certificate's names "
                                          f"(default wss://<this computer's IPv4>:{DEFAULT_SC_PORT}/)")
    parser.add_argument("--label-prefix", default=DEFAULT_LABEL_PREFIX,
                        help=f"device labels are <prefix>-01, -02, ... (default {DEFAULT_LABEL_PREFIX})")
    parser.add_argument("--device-instance", type=int,
                        help="first device's cert1/device-<n>/ (default: the label's number)")
    parser.add_argument("--port-id", default=DEFAULT_DEVICE_PORT_ID,
                        help=f"devices' cert1/device-<n>/port-<id>/ (default {DEFAULT_DEVICE_PORT_ID})")
    parser.add_argument("--portable", action="store_true",
                        help="leave this computer's host name out of the hub certificate (for a set that is "
                             "shared, like the demo set in certs/)")
    parser.add_argument("--force", action="store_true", help="delete an existing set first")
    args = parser.parse_args()

    if not 0 <= args.hub_device_instance <= 4194302:
        parser.error("--hub-device-instance must be 0 to 4194302")
    if args.device_instance is not None and not 0 <= args.device_instance <= 4194302:
        parser.error("--device-instance must be 0 to 4194302")
    if not is_valid_label(args.label_prefix):
        parser.error(f'--label-prefix "{args.label_prefix}" must be letters, digits, \'-\', \'_\' or \'.\', '
                     f'and not "{HUB_FILE_NAME}" or "{ISSUER_LABEL}"')
    if not args.port_id or re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', args.port_id):
        parser.error('--port-id may not contain < > : " / \\ | ? *')
    hub_uri = args.hub_uri or f"wss://{primary_ipv4()}:{DEFAULT_SC_PORT}/"
    cert_dir = Path(args.cert_dir)
    try:
        if args.add_devices:
            add_devices(cert_dir, args.hub_device_instance, args.add_devices, args.label_prefix,
                        args.device_instance, args.port_id, hub_uri)
        else:
            generate_set(cert_dir, args.hub_device_instance, args.devices, args.label_prefix,
                         args.device_instance, args.port_id, hub_uri, args.force, args.portable)
    except CertError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
