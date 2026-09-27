#!/usr/bin/env python
"""BACnet/SC certificate procedures over BACnet (ANSI/ASHRAE 135-2024 clause 19.8.3) - device-B side.

Drives the hub the way a certificate tool (e.g. the CAS BACnet Explorer's certificate page) does,
over plain BACnet/IP:

  Negative checks:
    - WriteProperty File_Size on the Certificate Signing Request (File 2) -> write-access-denied
    - ReinitializeDevice COLDSTART -> optional-functionality-not-supported
  Add issuer (cl. 19.8.3 "add issuer"):
    - WriteProperty File 4 File_Size = 0, AtomicWriteFile a second CA into it, read it back,
      Network Port 2 Changes_Pending = TRUE, ReinitializeDevice ACTIVATE_CHANGES
    - then a client certificate signed by the NEW CA completes a TLS handshake with the hub
  Rejected activation:
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
      private-key.pem is unchanged and the new key waits in private-key-pending.pem
    - sign the new CSR, write it into File 1, ACTIVATE_CHANGES -> the pending key replaces
      private-key.pem and the hub presents the newest certificate

Setup (two certificate sets from the example itself):
    BACnetExampleBSCHUB --sc-cert-dir hub-certs --generate-certs 1
    BACnetExampleBSCHUB --sc-cert-dir other-certs --generate-certs 1
    BACnetExampleBSCHUB --port 47870 --sc-port 47819 --sc-cert-dir hub-certs
    python tests/sc/cert_procedure_test.py --target-port 47870 --sc-port 47819 \\
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
from cryptography.x509.oid import ExtendedKeyUsageOID

# The nested choice classes aren't exported at module level - recover them from the Choice
# classes' own default field instances (same trick as file_object_test.py).
AtomicReadFileStreamAccess = type(AtomicReadFileRequestAccessMethodChoice.streamAccess)
AtomicWriteFileStreamAccess = type(AtomicWriteFileRequestAccessMethodChoice.streamAccess)

FILE_OPERATIONAL = 1
FILE_CSR = 2
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
    """Mutual-TLS handshake with the hub using clients/<label>/. Returns the hub's certificate (DER)."""
    folder = Path(cert_dir_of_client) / "clients" / label
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    if ca_file:
        ctx.load_verify_locations(cafile=str(ca_file))
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=str(folder / "operational-certificate.pem"), keyfile=str(folder / "private-key.pem"))
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock) as tls:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
                        b"Sec-WebSocket-Protocol: hub.bsc.bacnet.org\r\n\r\n")
            reply = tls.recv(1024)  # TLS 1.3 checks the client certificate after the handshake
            if b" 101 " not in reply.split(b"\r\n", 1)[0]:
                raise RuntimeError(f"WebSocket upgrade refused: {reply[:60]!r}")
            return tls.getpeercert(binary_form=True)


def sign_csr(csr_pem, ca_dir):
    """Signs the hub's CSR with another lab CA - what a site CA does in the procedure."""
    csr = x509.load_pem_x509_csr(csr_pem)
    ca_cert = x509.load_pem_x509_certificate((Path(ca_dir) / "issuer-certificate.pem").read_bytes())
    ca_key = serialization.load_pem_private_key((Path(ca_dir) / "issuer-private-key.pem").read_bytes(), None)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(csr.subject).issuer_name(ca_cert.subject).public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM), cert.public_bytes(serialization.Encoding.DER)


async def main():
    parser = SimpleArgumentParser()
    parser.set_defaults(address="127.0.0.1/32:47811")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=47808)
    parser.add_argument("--sc-port", type=int, default=47819)
    parser.add_argument("--cert-dir", required=True, help="the hub's --sc-cert-dir (REWRITTEN by this test)")
    parser.add_argument("--second-issuer-dir", required=True, help="another --generate-certs set: the new CA")
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

        # --- Changes_Pending before any write (issue #41) ---------------------------------------
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

        # --- add issuer -----------------------------------------------------------------------
        new_ca = (other_dir / "issuer-certificate.pem").read_bytes()
        await write_file(app, device, FILE_ISSUER_2, new_ca)
        record("File 4 reads back the staged issuer", await read_file(app, device, FILE_ISSUER_2) == new_ca)
        pending = await app.read_property(device, ObjectIdentifier(("network-port", SC_NETWORK_PORT)), PROPERTY_CHANGES_PENDING)
        record("Network Port 2 Changes_Pending after the write", bool(pending), str(pending))
        record("issuer-certificate-2.pem not written before activation",
               not (hub_dir / "issuer-certificate-2.pem").exists())
        response = await reinitialize(app, device, "activateChanges")
        record("ACTIVATE_CHANGES (add issuer) acknowledged", isinstance(response, SimpleAckPDU), str(response))
        pending = await app.read_property(device, ObjectIdentifier(("network-port", SC_NETWORK_PORT)), PROPERTY_CHANGES_PENDING)
        record("Network Port 2 Changes_Pending FALSE after ACTIVATE_CHANGES", not pending, str(pending))
        record("issuer-certificate-2.pem written on activation",
               (hub_dir / "issuer-certificate-2.pem").read_bytes() == new_ca)
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
        before = (hub_dir / "operational-certificate.pem").read_bytes()
        await write_file(app, device, FILE_OPERATIONAL, b"this is not a certificate\n")
        response = await reinitialize(app, device, "activateChanges")
        record("ACTIVATE_CHANGES with a garbage operational certificate refused",
               "invalid-configuration-data" in error_text(response), error_text(response))
        record("operational certificate on disk unchanged after the refusal",
               (hub_dir / "operational-certificate.pem").read_bytes() == before)

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
                                      ca_file=other_dir / "issuer-certificate.pem")
            record("hub presents the NEW operational certificate", presented == new_cert_der)
        except Exception as e:
            record("hub presents the NEW operational certificate", False, str(e))

        # --- replace operational certificate with a new key pair (GENERATE_CSR_FILE) ----------
        key_before = (hub_dir / "private-key.pem").read_bytes()
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
        record("private-key.pem unchanged until activation", (hub_dir / "private-key.pem").read_bytes() == key_before)
        record("the new key waits in private-key-pending.pem", (hub_dir / "private-key-pending.pem").is_file())
        try:
            presented = tls_handshake(args.target, args.sc_port, other_dir, "client-01",
                                      ca_file=other_dir / "issuer-certificate.pem")
            record("hub still presents its current certificate before activation", presented == new_cert_der)
        except Exception as e:
            record("hub still presents its current certificate before activation", False, str(e))
        newest_pem, newest_der = sign_csr(new_csr, other_dir)
        await write_file(app, device, FILE_OPERATIONAL, newest_pem)
        response = await reinitialize(app, device, "activateChanges")
        record("ACTIVATE_CHANGES (certificate for the new key) acknowledged",
               isinstance(response, SimpleAckPDU), str(response))
        record("the pending key replaced private-key.pem",
               not (hub_dir / "private-key-pending.pem").exists() and
               (hub_dir / "private-key.pem").read_bytes() != key_before)
        await asyncio.sleep(2)
        try:
            presented = tls_handshake(args.target, args.sc_port, other_dir, "client-01",
                                      ca_file=other_dir / "issuer-certificate.pem")
            record("hub presents the certificate for its NEW key", presented == newest_der)
        except Exception as e:
            record("hub presents the certificate for its NEW key", False, str(e))
    finally:
        app.close()

    failed = [name for name, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
