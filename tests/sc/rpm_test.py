#!/usr/bin/env python
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""RPM (ReadPropertyMultiple, DS-RPM-B) against the running B-SCHUB example, over BACnet/SC.

Connects to the hub as a BACnet/SC device (sc_client.py), finds the hub's own
device with Who-Is, and reads the Device object's Object_Name + Vendor_Identifier
in ONE ReadPropertyMultiple request, confirming a real multi-property response
(not an error/abort).

Usage (the example running with --sc-port 4443 on the demo certificates):
    python tests/sc/rpm_test.py --sc-port 4443 --cert-dir certs
"""
import argparse
import asyncio
import sys

from bacpypes3.apdu import (
    ErrorRejectAbortNack,
    PropertyReference,
    ReadAccessSpecification,
    ReadPropertyMultipleACK,
    ReadPropertyMultipleRequest,
)
from bacpypes3.basetypes import PropertyIdentifier
from bacpypes3.primitivedata import CharacterString, ObjectIdentifier, Unsigned

from sc_client import ScClient


async def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--sc-port", type=int, default=4443, help="the example's BACnet/SC port")
    parser.add_argument("--cert-dir", default="certs", help="certificate set with a device (client) certificate")
    parser.add_argument("--device-instance", type=int, default=389022)
    args = parser.parse_args()

    async with ScClient(args.sc_port, args.cert_dir, host=args.host) as client:
        device_address = await client.find_device(args.device_instance)
        print(f"PASS: Device {args.device_instance} answered Who-Is through the hub (VMAC {device_address})")
        spec = ReadAccessSpecification(
            objectIdentifier=ObjectIdentifier(("device", args.device_instance)),
            listOfPropertyReferences=[
                PropertyReference(propertyIdentifier=PropertyIdentifier("objectName")),
                PropertyReference(propertyIdentifier=PropertyIdentifier("vendorIdentifier")),
            ],
        )
        request = ReadPropertyMultipleRequest(listOfReadAccessSpecs=[spec], destination=device_address)
        response = await client.app.request(request)
        if isinstance(response, ErrorRejectAbortNack):
            print(f"FAIL: ReadPropertyMultiple returned an error/reject/abort: {response}")
            return 1
        if not isinstance(response, ReadPropertyMultipleACK):
            print(f"FAIL: unexpected response type {type(response)!r}: {response!r}")
            return 1

        result = response.listOfReadAccessResults[0]
        values = {}
        for item in result.listOfResults:
            prop = str(item.propertyIdentifier)
            if item.readResult.propertyValue is not None:
                raw = item.readResult.propertyValue
                if prop == "object-name":
                    values[prop] = raw.cast_out(CharacterString)
                elif prop == "vendor-identifier":
                    values[prop] = int(raw.cast_out(Unsigned))
                else:
                    values[prop] = raw
            else:
                values[prop] = f"ERROR: {item.readResult.propertyAccessError}"
        print(f"PASS: ReadPropertyMultiple ACK received for Device {args.device_instance}: {values}")
        if values.get("object-name") != "Chipkin Example B-SCHUB" or values.get("vendor-identifier") != 389:
            print("FAIL: expected Object_Name=Chipkin Example B-SCHUB, Vendor_Identifier=389")
            return 1
        print("PASS: decoded values match expected Object_Name=Chipkin Example B-SCHUB, Vendor_Identifier=389")

        # BACnet/SC only: Network Port 2 (BACnet/SC) is the device's only Network Port.
        device_id = ObjectIdentifier(("device", args.device_instance))
        object_list = [str(o) for o in await client.app.read_property(device_address, device_id, "object-list")]
        ports = [o for o in object_list if o.startswith("network-port")]
        if ports != ["network-port,2"]:
            print(f"FAIL: expected exactly one Network Port (2, BACnet/SC) in Object_List, got {ports}")
            return 1
        print(f"PASS: Object_List has one Network Port, network-port,2 (BACnet/SC): {object_list}")
        revision = int(await client.app.read_property(device_address, device_id, "protocol-revision"))
        if revision != 30:
            print(f"FAIL: Protocol_Revision is {revision}, expected 30")
            return 1
        print("PASS: Protocol_Revision is 30")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
