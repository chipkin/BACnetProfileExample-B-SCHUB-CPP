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
  Replace operational certificate (cl. 19.8.3 "replace operational certificate", existing CSR):
    - read the CSR (File 2), sign it with the second CA, write it into File 1, ACTIVATE_CHANGES
    - then the hub presents the NEW certificate in its TLS handshake

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
from bacpypes3.primitivedata import ObjectIdentifier, Unsigned
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
    finally:
        app.close()

    failed = [name for name, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
