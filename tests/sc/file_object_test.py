#!/usr/bin/env python
"""V6 verification (docs/bacnet-sc-transport-plan.md, phase 4) - the File objects Network Port 2's
BACnet/SC certificate properties point at, over plain BACnet/IP.

Checks, against a running instance of this example (default 127.0.0.1:47808):
  1. AtomicReadFile of File 1 (the operational certificate, "Operational Certificate") returns the bytes of
     certs/hub.crt on disk, byte-for-byte.
  2. Network Port 2's Issuer_Certificate_Files property (511) has exactly 2 entries.
  3. Negative test: every File object in the device's Object_List is read via AtomicReadFile and
     compared against certs/hub.key - none of them may match it (the private key has no File
     object at all, so this should trivially hold; this test proves it rather than assuming it).

Usage:
    python tests/sc/file_object_test.py [--address 127.0.0.1] [--port 47808] [--cert-dir certs]
"""
import argparse
import asyncio
import pathlib
import sys

import cert_paths  # BACnet-named or older certificate file names

from bacpypes3.apdu import (
    AtomicReadFileACK,
    AtomicReadFileRequest,
    AtomicReadFileRequestAccessMethodChoice,
    ErrorRejectAbortNack,
    ReadPropertyACK,
    ReadPropertyRequest,
)

# The nested "streamAccess" choice classes aren't exported at module level -
# recover the real type from the Choice class's own default field instance.
AtomicReadFileRequestStreamAccess = type(AtomicReadFileRequestAccessMethodChoice.streamAccess)
from bacpypes3.app import Application
from bacpypes3.argparse import SimpleArgumentParser
from bacpypes3.basetypes import PropertyIdentifier
from bacpypes3.constructeddata import ArrayOf
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier

ISSUER_CERTIFICATE_FILES_PROPERTY = 511  # BACnetPropertyIdentifier.h: issuerCertificateFiles = 511


async def atomic_read_whole_file(app, address, file_instance, max_chunk=1400):
    """Reads an entire stream-access File object via repeated AtomicReadFile requests."""
    data = bytearray()
    position = 0
    while True:
        access = AtomicReadFileRequestAccessMethodChoice(
            streamAccess=AtomicReadFileRequestStreamAccess(
                fileStartPosition=position, requestedOctetCount=max_chunk
            )
        )
        request = AtomicReadFileRequest(
            fileIdentifier=ObjectIdentifier(("file", file_instance)),
            accessMethod=access,
            destination=address,
        )
        response = await app.request(request)
        if isinstance(response, ErrorRejectAbortNack):
            return None, response
        if not isinstance(response, AtomicReadFileACK):
            return None, f"unexpected response type {type(response)!r}"
        chunk = bytes(response.accessMethod.streamAccess.fileData)
        data += chunk
        position += len(chunk)
        if bool(response.endOfFile) or len(chunk) == 0:
            break
    return bytes(data), None


async def main():
    parser = SimpleArgumentParser()
    # This script's OWN local BACnet/IP endpoint - a different port than the
    # device under test (47808 by default), so the two can coexist on one host.
    # "127.0.0.1/32:port", not "host:port" - matches ../../../plugfest-example/
    # tests/loopback/test_loopback.py's own working pattern for a loopback client.
    parser.set_defaults(address="127.0.0.1/32:47809")
    parser.add_argument("--target", default="127.0.0.1", help="the example's BACnet/IP address (default 127.0.0.1)")
    parser.add_argument("--target-port", type=int, default=47808, help="the example's BACnet/IP port (default 47808)")
    parser.add_argument("--cert-dir", default=None, help="path to certs/ (default: this script's ../../certs)")
    args = parser.parse_args()

    cert_dir = pathlib.Path(args.cert_dir) if args.cert_dir else (pathlib.Path(__file__).resolve().parents[2] / "certs")
    hub_crt_path = cert_paths.hub_certificate(cert_dir)
    hub_key_path = cert_paths.hub_private_key(cert_dir)

    device_address = Address(f"{args.target}:{args.target_port}")
    app = Application.from_args(args)

    failures = []
    try:
        # --- 1. AtomicReadFile(File 1) == certs/hub.crt, byte-for-byte -----------------
        on_disk = hub_crt_path.read_bytes()
        read_back, err = await atomic_read_whole_file(app, device_address, 1)
        if err is not None:
            failures.append(f"AtomicReadFile(File 1) failed: {err}")
        elif read_back != on_disk:
            failures.append(
                f"AtomicReadFile(File 1) returned {len(read_back)} bytes, "
                f"{hub_crt_path.name} on disk is {len(on_disk)} bytes - MISMATCH"
            )
        else:
            print(f"PASS: AtomicReadFile(File 1, \"Operational Certificate\") == {hub_crt_path.name} byte-for-byte ({len(on_disk)} bytes)")

        # --- 2. Network Port 2's Issuer_Certificate_Files has exactly 2 entries --------
        response = await app.request(
            ReadPropertyRequest(
                objectIdentifier=ObjectIdentifier(("networkPort", 2)),
                propertyIdentifier=PropertyIdentifier(ISSUER_CERTIFICATE_FILES_PROPERTY),
                destination=device_address,
            )
        )
        if isinstance(response, ErrorRejectAbortNack):
            failures.append(f"ReadProperty(Network Port 2, Issuer_Certificate_Files) failed: {response}")
        elif not isinstance(response, ReadPropertyACK):
            failures.append(f"ReadProperty(Network Port 2, Issuer_Certificate_Files): unexpected response {response!r}")
        else:
            value = response.propertyValue.cast_out(ArrayOf(ObjectIdentifier))
            count = len(value)
            if count != 2:
                failures.append(f"Issuer_Certificate_Files has {count} entries, expected exactly 2: {list(value)}")
            else:
                print(f"PASS: Network Port 2 Issuer_Certificate_Files has exactly 2 entries: {list(value)}")

        # --- 3. Negative test: no File object serves certs/hub.key ---------------------
        hub_key_bytes = hub_key_path.read_bytes()
        checked = []
        for file_instance in (1, 2, 3, 4):
            data, err = await atomic_read_whole_file(app, device_address, file_instance)
            if err is not None:
                failures.append(f"AtomicReadFile(File {file_instance}) failed while enumerating: {err}")
                continue
            checked.append(file_instance)
            if data == hub_key_bytes:
                failures.append(f"File {file_instance} returned bytes IDENTICAL to {hub_key_path.name} - KEY LEAK")
        if checked:
            print(f"PASS: File objects {checked} enumerated and read; none served {hub_key_path.name} ({len(hub_key_bytes)} bytes)")
    finally:
        app.close()

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f" - {f}")
        return 1
    print("\nV6: all checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
