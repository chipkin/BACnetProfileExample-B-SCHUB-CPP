#!/usr/bin/env python
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""BACnet/SC certificate procedures over BACnet (ANSI/ASHRAE 135-2024 clause 19.8.3) - device-B side.

Drives the hub the way a certificate tool (e.g. the CAS BACnet Explorer's certificate page) does,
over plain BACnet/IP:

  Negative checks:
    - WriteProperty File_Size on the Certificate Signing Request (File 2) -> write-access-denied
    - ReinitializeDevice COLDSTART -> optional-functionality-not-supported
  Removing the only issuer:
    - with slot 2 still serving slot 1, empty File 3 and ACTIVATE_CHANGES -> refused
      (invalid-configuration-data); then write the original issuer back into File 3
  Add issuer (cl. 19.8.3 "add issuer"):
    - WriteProperty File 4 File_Size = 0, AtomicWriteFile a second CA into it, read it back,
      Network Port 2 Changes_Pending = TRUE, ReinitializeDevice ACTIVATE_CHANGES
    - then a client certificate signed by the NEW CA completes a TLS handshake with the hub
  Rejected activation:
    - the current certificate with its private key appended (a combined file) into File 1,
      ACTIVATE_CHANGES -> invalid-configuration-data (File 1 is public over AtomicReadFile)
    - AtomicWriteFile garbage into File 1, ACTIVATE_CHANGES -> invalid-configuration-data,
      and the operational certificate on disk is unchanged
  DISCARD_CHANGES (Network Port 2 Command, cl. 12.56.16/.100):
    - with the garbage still staged, GENERATE_CSR_FILE -> invalid-value-in-this-state
    - DISCARD_CHANGES -> Changes_Pending FALSE, File 1 reads the certificate on disk again
  Replace operational certificate (cl. 19.8.3 "replace operational certificate", existing CSR):
    - read the CSR (File 2), sign it with the second CA, write it into File 1, ACTIVATE_CHANGES
    - then the hub presents the NEW certificate in its TLS handshake
  Replace operational certificate with a new key pair (GENERATE_CSR_FILE):
    - Command GENERATE_CSR_FILE -> a new CSR for a new key; Command reads IDLE again;
      the hub's key (key-hub.pem) is unchanged and the new key waits in key-hub-pending.pem
    - sign the new CSR, write it into File 1, ACTIVATE_CHANGES -> the pending key replaces
      key-hub.pem and the hub presents the newest certificate
  Certificates peers would refuse, and a root + intermediate set:
    - a CA certificate, or one with EKU clientAuth only, as File 1 -> invalid-configuration-data
    - root CA in File 3, an intermediate CA in File 4, a leaf from the intermediate in File 1
      -> ACTIVATE_CHANGES acknowledged

Setup (two certificate sets from the example itself):
    python tools/make_test_certs.py --cert-dir hub-certs --devices 1
    python tools/make_test_certs.py --cert-dir other-certs --devices 1
    BACnetExampleBSCHUB --port 47870 --sc-port 4443 --sc-cert-dir hub-certs
    python tests/sc/cert_procedure_test.py --target-port 47870 --sc-port 4443 \\
        --cert-dir hub-certs --second-issuer-dir other-certs

WARNING: this rewrites the hub's certificate files in --cert-dir. Use a throwaway set.
Exit code 0 = every check passed.
"""
import asyncio
import datetime
import socket
import ssl
import sys
from pathlib import Path

import cert_paths

from bacpypes3.apdu import (
    AtomicReadFileACK,
    AtomicReadFileRequest,
    AtomicReadFileRequestAccessMethodChoice,
    AtomicWriteFileACK,
    AtomicWriteFileRequest,
    AtomicWriteFileRequestAccessMethodChoice,
    ErrorRejectAbortNack,
    ReinitializeDeviceRequest,
    SimpleAckPDU,
)
from bacpypes3.app import Application
from bacpypes3.argparse import SimpleArgumentParser
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import Enumerated, ObjectIdentifier, Unsigned
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# The nested choice classes aren't exported at module level - recover them from the Choice
# classes' own default field instances (same trick as file_object_test.py).
AtomicReadFileStreamAccess = type(AtomicReadFileRequestAccessMethodChoice.streamAccess)
AtomicWriteFileStreamAccess = type(AtomicWriteFileRequestAccessMethodChoice.streamAccess)

FILE_OPERATIONAL = 1
FILE_CSR = 2
FILE_ISSUER_1 = 3
FILE_ISSUER_2 = 4
SC_NETWORK_PORT = 2
PROPERTY_FILE_SIZE = "file-size"
PROPERTY_CHANGES_PENDING = "changes-pending"
PROPERTY_COMMAND = "command"
# BACnetNetworkPortCommand (cl. 12.56.16). bacpypes3 has no name for 9, so send raw values.
COMMAND_IDLE = 0
COMMAND_DISCARD_CHANGES = 1
COMMAND_GENERATE_CSR_FILE = 9

results = []


def record(name, ok, detail=""):
    results.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" - {detail}" if detail else ""))


def error_text(response):
    return str(response)


async def read_file(app, address, instance):
    data, position = bytearray(), 0
    while True:
        request = AtomicReadFileRequest(
            fileIdentifier=ObjectIdentifier(("file", instance)),
            accessMethod=AtomicReadFileRequestAccessMethodChoice(
                streamAccess=AtomicReadFileStreamAccess(fileStartPosition=position, requestedOctetCount=1024)),
            destination=address)
        response = await app.request(request)
        if not isinstance(response, AtomicReadFileACK):
            raise RuntimeError(f"AtomicReadFile File {instance}: {response}")
        chunk = bytes(response.accessMethod.streamAccess.fileData)
        data += chunk
        position += len(chunk)
        if bool(response.endOfFile) or not chunk:
            return bytes(data)


async def write_file(app, address, instance, data, chunk=400):
    """File_Size = 0, then AtomicWriteFile the data in chunks - the clause 19.8.3 sequence."""
    await app.write_property(address, ObjectIdentifier(("file", instance)), PROPERTY_FILE_SIZE, Unsigned(0))
    for start in range(0, len(data), chunk):
        request = AtomicWriteFileRequest(
            fileIdentifier=ObjectIdentifier(("file", instance)),
            accessMethod=AtomicWriteFileRequestAccessMethodChoice(
                streamAccess=AtomicWriteFileStreamAccess(fileStartPosition=start, fileData=data[start:start + chunk])),
            destination=address)
        response = await app.request(request)
        if not isinstance(response, AtomicWriteFileACK):
            raise RuntimeError(f"AtomicWriteFile File {instance} @ {start}: {response}")


async def reinitialize(app, address, state):
    """The response PDU, or the error bacpypes3 raised for an Error/Reject/Abort."""
    request = ReinitializeDeviceRequest(reinitializedStateOfDevice=state, destination=address)
    try:
        return await app.request(request)
    except BaseException as e:  # bacpypes3's Error is not an Exception subclass
        return e


async def write_command(app, address, command):
    """WriteProperty Network Port 2 Command. None on success, else the error text."""
    try:
        await app.write_property(address, ObjectIdentifier(("network-port", SC_NETWORK_PORT)),
                                 PROPERTY_COMMAND, Enumerated(command))
        return None
    except BaseException as e:  # bacpypes3's Error is not an Exception subclass
        return str(e) or type(e).__name__


def tls_handshake(host, port, cert_dir_of_client, label, ca_file=None):
    """Mutual-TLS handshake with the hub using the device <label>'s files. Returns the hub's certificate (DER)."""
    certfile, keyfile = cert_paths.client_files(Path(cert_dir_of_client), label)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    if ca_file:
        ctx.load_verify_locations(cafile=str(ca_file))
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock) as tls:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
                        b"Sec-WebSocket-Protocol: hub.bsc.bacnet.org\r\n\r\n")
            reply = tls.recv(1024)  # TLS 1.3 checks the client certificate after the handshake
            if b" 101 " not in reply.split(b"\r\n", 1)[0]:
                raise RuntimeError(f"WebSocket upgrade refused: {reply[:60]!r}")
            return tls.getpeercert(binary_form=True)


def sign_csr(csr_pem, ca_dir, ca=None, is_ca=False, eku=None):
    """Signs the hub's CSR with another lab CA - what a site CA does in the procedure.
    `ca` = (certificate, key) overrides ca_dir; is_ca/eku make deliberately wrong certificates."""
    csr = x509.load_pem_x509_csr(csr_pem)
    if ca is None:
        ca_cert_path, ca_key_path = cert_paths.ca_files(Path(ca_dir))
        ca = (x509.load_pem_x509_certificate(ca_cert_path.read_bytes()),
              serialization.load_pem_private_key(ca_key_path.read_bytes(), None))
    ca_cert, ca_key = ca
    if eku is None:
        eku = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(csr.subject).issuer_name(ca_cert.subject).public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=is_ca)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM), cert.public_bytes(serialization.Encoding.DER)


def make_intermediate(ca_dir):
    """An intermediate CA signed by ca_dir's lab CA: (certificate, key, certificate PEM)."""
    ca_cert_path, ca_key_path = cert_paths.ca_files(Path(ca_dir))
    root = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    root_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cert_procedure_test intermediate CA")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(root.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
    return cert, key, cert.public_bytes(serialization.Encoding.PEM)


async def main():
    parser = SimpleArgumentParser()
    parser.set_defaults(address="127.0.0.1/32:47811")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=47808)
    parser.add_argument("--sc-port", type=int, default=4443)
    parser.add_argument("--cert-dir", required=True, help="the hub's --sc-cert-dir (REWRITTEN by this test)")
    parser.add_argument("--second-issuer-dir", required=True, help="another tools/make_test_certs.py set: the new CA")
    args = parser.parse_args()
    hub_dir, other_dir = Path(args.cert_dir), Path(args.second_issuer_dir)
    device = Address(f"{args.target}:{args.target_port}")
    app = Application.from_args(args)
    try:
        # --- negative checks ------------------------------------------------------------------
        try:
            await app.write_property(device, ObjectIdentifier(("file", FILE_CSR)), PROPERTY_FILE_SIZE, Unsigned(0))
            record("CSR File_Size write refused", False, "write was accepted")
        except BaseException as e:  # bacpypes3's Error is not an Exception subclass
            record("CSR File_Size write refused", "write-access-denied" in str(e), str(e))
        response = await reinitialize(app, device, "coldstart")
        record("ReinitializeDevice COLDSTART refused",
               "optional-functionality-not-supported" in error_text(response), error_text(response))

        # --- Changes_Pending before any write -----------------------------------------------------
        # Should be FALSE: nothing has been written. The stack reports TRUE on every start
        # (cas-bacnet-stack#2866: SetBACnetSCCertificateFileObjects leaves its own start-up
        # binding pending), so this is reported as a known issue rather than failed. When it
        # reads FALSE, #2866 is fixed: make this a normal record().
        pending = await app.read_property(device, ObjectIdentifier(("network-port", SC_NETWORK_PORT)), PROPERTY_CHANGES_PENDING)
        if pending:
            print("KNOWN ISSUE: Network Port 2 Changes_Pending is TRUE before any write "
                  "(#41, cas-bacnet-stack#2866) - not counted as a failure")
        else:
            record("Network Port 2 Changes_Pending FALSE before any write (cas-bacnet-stack#2866 fixed)", True)

        # --- removing the only issuer ----------------------------------------------------------
        # Slot 2 has no file of its own yet, so it serves slot 1. Emptying slot 1 must not pass
        # validation on the strength of slot 1's OLD contents seen through slot 2.
        await app.write_property(device, ObjectIdentifier(("file", FILE_ISSUER_1)), PROPERTY_FILE_SIZE, Unsigned(0))
        record("File 4 follows the staged (empty) slot 1", await read_file(app, device, FILE_ISSUER_2) == b"")
        response = await reinitialize(app, device, "activateChanges")
        record("ACTIVATE_CHANGES with no issuer left refused",
               "invalid-configuration-data" in error_text(response), error_text(response))
        record("issuer slot 1 file unchanged", cert_paths.issuer_certificate(hub_dir).stat().st_size > 0)
        # Put the original back (staged; activated with the next step). Not DISCARD_CHANGES here:
        # on a fresh hub it also reverts the stack's own start-up pending state (#41,
        # cas-bacnet-stack#2866), after which Changes_Pending no longer follows certificate writes.
        await write_file(app, device, FILE_ISSUER_1, cert_paths.issuer_certificate(hub_dir).read_bytes())

        # --- add issuer -----------------------------------------------------------------------
        new_ca = cert_paths.issuer_certificate(other_dir).read_bytes()
        await write_file(app, device, FILE_ISSUER_2, new_ca)
        record("File 4 reads back the staged issuer", await read_file(app, device, FILE_ISSUER_2) == new_ca)
        pending = await app.read_property(device, ObjectIdentifier(("network-port", SC_NETWORK_PORT)), PROPERTY_CHANGES_PENDING)
        record("Network Port 2 Changes_Pending after the write", bool(pending), str(pending))
        record("issuer slot 2 file not written before activation",
               not cert_paths.issuer_certificate_2(hub_dir).exists())
        response = await reinitialize(app, device, "activateChanges")
        record("ACTIVATE_CHANGES (add issuer) acknowledged", isinstance(response, SimpleAckPDU), str(response))
        pending = await app.read_property(device, ObjectIdentifier(("network-port", SC_NETWORK_PORT)), PROPERTY_CHANGES_PENDING)
        record("Network Port 2 Changes_Pending FALSE after ACTIVATE_CHANGES", not pending, str(pending))
        record("issuer slot 2 file written on activation",
               cert_paths.issuer_certificate_2(hub_dir).read_bytes() == new_ca)
        await asyncio.sleep(2)  # the main loop reloads TLS on its next pass
        try:
            tls_handshake(args.target, args.sc_port, other_dir, "client-01")
            record("client signed by the NEW issuer is accepted", True)
        except Exception as e:
            record("client signed by the NEW issuer is accepted", False, str(e))
        try:
            tls_handshake(args.target, args.sc_port, hub_dir, "client-01")
            record("client signed by the ORIGINAL issuer is still accepted", True)
        except Exception as e:
            record("client signed by the ORIGINAL issuer is still accepted", False, str(e))

        # --- rejected activation --------------------------------------------------------------
        before = cert_paths.hub_certificate(hub_dir).read_bytes()
        await write_file(app, device, FILE_OPERATIONAL, before + cert_paths.hub_private_key(hub_dir).read_bytes())
        response = await reinitialize(app, device, "activateChanges")
        record("ACTIVATE_CHANGES with a private key in the certificate file refused",
               "invalid-configuration-data" in error_text(response), error_text(response))
        await write_file(app, device, FILE_OPERATIONAL, b"this is not a certificate\n")
        response = await reinitialize(app, device, "activateChanges")
        record("ACTIVATE_CHANGES with a garbage operational certificate refused",
               "invalid-configuration-data" in error_text(response), error_text(response))
        record("operational certificate on disk unchanged after the refusal",
               cert_paths.hub_certificate(hub_dir).read_bytes() == before)

        # --- DISCARD_CHANGES (Network Port 2 Command) -----------------------------------------
        # The garbage from the refused activation is still staged.
        error = await write_command(app, device, COMMAND_GENERATE_CSR_FILE)
        record("GENERATE_CSR_FILE with changes pending refused (invalid-value-in-this-state)",
               error is not None and "invalid-value-in-this-state" in error, str(error))
        error = await write_command(app, device, COMMAND_DISCARD_CHANGES)
        record("Command DISCARD_CHANGES acknowledged", error is None, str(error))
        pending = await app.read_property(device, ObjectIdentifier(("network-port", SC_NETWORK_PORT)), PROPERTY_CHANGES_PENDING)
        record("Network Port 2 Changes_Pending FALSE after DISCARD_CHANGES", not pending, str(pending))
        record("File 1 reads the certificate on disk again after DISCARD_CHANGES",
               await read_file(app, device, FILE_OPERATIONAL) == before)

        # --- replace operational certificate (existing CSR) -----------------------------------
        csr = await read_file(app, device, FILE_CSR)
        new_cert_pem, new_cert_der = sign_csr(csr, other_dir)
        await write_file(app, device, FILE_OPERATIONAL, new_cert_pem)
        response = await reinitialize(app, device, "activateChanges")
        record("ACTIVATE_CHANGES (replace operational) acknowledged", isinstance(response, SimpleAckPDU), str(response))
        await asyncio.sleep(2)
        try:
            presented = tls_handshake(args.target, args.sc_port, other_dir, "client-01",
                                      ca_file=cert_paths.issuer_certificate(other_dir))
            record("hub presents the NEW operational certificate", presented == new_cert_der)
        except Exception as e:
            record("hub presents the NEW operational certificate", False, str(e))

        # --- replace operational certificate with a new key pair (GENERATE_CSR_FILE) ----------
        key_before = cert_paths.hub_private_key(hub_dir).read_bytes()
        error = await write_command(app, device, COMMAND_GENERATE_CSR_FILE)
        record("Command GENERATE_CSR_FILE acknowledged", error is None, str(error))
        command = await app.read_property(device, ObjectIdentifier(("network-port", SC_NETWORK_PORT)), PROPERTY_COMMAND)
        record("Network Port 2 Command reads IDLE after GENERATE_CSR_FILE", int(command) == COMMAND_IDLE, str(command))
        new_csr = await read_file(app, device, FILE_CSR)
        new_csr_obj = x509.load_pem_x509_csr(new_csr)
        record("File 2 holds a NEW, valid certificate signing request",
               new_csr != csr and new_csr_obj.is_signature_valid)
        record("the new CSR keeps the hub's subject",
               new_csr_obj.subject == x509.load_pem_x509_certificate(new_cert_pem).subject)
        record("the hub key unchanged until activation", cert_paths.hub_private_key(hub_dir).read_bytes() == key_before)
        record("the new key waits in the pending key file", cert_paths.pending_private_key(hub_dir).is_file())
        try:
            presented = tls_handshake(args.target, args.sc_port, other_dir, "client-01",
                                      ca_file=cert_paths.issuer_certificate(other_dir))
            record("hub still presents its current certificate before activation", presented == new_cert_der)
        except Exception as e:
            record("hub still presents its current certificate before activation", False, str(e))
        newest_pem, newest_der = sign_csr(new_csr, other_dir)
        await write_file(app, device, FILE_OPERATIONAL, newest_pem)
        response = await reinitialize(app, device, "activateChanges")
        record("ACTIVATE_CHANGES (certificate for the new key) acknowledged",
               isinstance(response, SimpleAckPDU), str(response))
        record("the pending key replaced the hub key",
               not cert_paths.pending_private_key(hub_dir).exists() and
               cert_paths.hub_private_key(hub_dir).read_bytes() != key_before)
        await asyncio.sleep(2)
        try:
            presented = tls_handshake(args.target, args.sc_port, other_dir, "client-01",
                                      ca_file=cert_paths.issuer_certificate(other_dir))
            record("hub presents the certificate for its NEW key", presented == newest_der)
        except Exception as e:
            record("hub presents the certificate for its NEW key", False, str(e))

        # --- certificates peers would refuse, and a root + intermediate set --------------------
        for label, kwargs in (("a CA certificate", {"is_ca": True}),
                              ("EKU clientAuth only", {"eku": [ExtendedKeyUsageOID.CLIENT_AUTH]})):
            bad_pem, _ = sign_csr(new_csr, other_dir, **kwargs)
            await write_file(app, device, FILE_OPERATIONAL, bad_pem)
            response = await reinitialize(app, device, "activateChanges")
            record(f"ACTIVATE_CHANGES with {label} as the operational certificate refused",
                   "invalid-configuration-data" in error_text(response), error_text(response))
        inter_cert, inter_key, inter_pem = make_intermediate(other_dir)
        leaf_pem, _ = sign_csr(new_csr, None, ca=(inter_cert, inter_key))
        await write_file(app, device, FILE_ISSUER_1, cert_paths.issuer_certificate(other_dir).read_bytes())
        await write_file(app, device, FILE_ISSUER_2, inter_pem)
        await write_file(app, device, FILE_OPERATIONAL, leaf_pem)
        response = await reinitialize(app, device, "activateChanges")
        record("ACTIVATE_CHANGES with root (slot 1) + intermediate (slot 2) + leaf acknowledged",
               isinstance(response, SimpleAckPDU), error_text(response))
    finally:
        app.close()

    failed = [name for name, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
