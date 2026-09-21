#!/usr/bin/env python
"""Ad hoc RPM (ReadPropertyMultiple) verification against the running B-SCHUB example.

Reads the Device object's Object_Name + Vendor_Identifier in ONE ReadPropertyMultiple
request, confirming a real multi-property response (not an error/abort).

Usage:
    python rpm_test.py --target 127.0.0.1 --target-port 47870
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
from bacpypes3.app import Application
from bacpypes3.argparse import SimpleArgumentParser
from bacpypes3.basetypes import PropertyIdentifier
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier


async def main():
    parser = SimpleArgumentParser()
    parser.set_defaults(address="127.0.0.1/32:47871")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=47870)
    parser.add_argument("--device-instance", type=int, default=389022)
    args = parser.parse_args()

    device_address = Address(f"{args.target}:{args.target_port}")
    app = Application.from_args(args)

    try:
        spec = ReadAccessSpecification(
            objectIdentifier=ObjectIdentifier(("device", args.device_instance)),
            listOfPropertyReferences=[
                PropertyReference(propertyIdentifier=PropertyIdentifier("objectName")),
                PropertyReference(propertyIdentifier=PropertyIdentifier("vendorIdentifier")),
            ],
        )
        request = ReadPropertyMultipleRequest(
            listOfReadAccessSpecs=[spec],
            destination=device_address,
        )
        response = await app.request(request)
        if isinstance(response, ErrorRejectAbortNack):
            print(f"FAIL: ReadPropertyMultiple returned an error/reject/abort: {response}")
            return 1
        if not isinstance(response, ReadPropertyMultipleACK):
            print(f"FAIL: unexpected response type {type(response)!r}: {response!r}")
            return 1

        from bacpypes3.primitivedata import CharacterString, Unsigned

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
        assert values.get("object-name") == "Rainbow", "unexpected Object_Name"
        assert values.get("vendor-identifier") == 389, "unexpected Vendor_Identifier"
        print("PASS: decoded values match expected Object_Name=Rainbow, Vendor_Identifier=389")
        return 0
    finally:
        app.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
