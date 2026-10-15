#!/usr/bin/env python
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""Discovery over BACnet/SC: read every property the hub's own device says it has, the way a client does.

    python tests/sc/discovery_test.py --sc-port 4443 --cert-dir certs

The series' discovery Wire Test (B-SS-CPP tests/discovery_test.py) does this over BACnet/IP.
This example has no BACnet/IP port, so this is the same walk over BACnet/SC: connect to the
hub as a BACnet/SC device (sc_client.py), then

    1. Who-Is   -> the I-Am of Device 389022
    2. ReadProperty Device Object_List (control: exactly EXPECTED_OBJECTS)
    3. for every object: ReadProperty Property_List, then ReadProperty of every property it
       lists (and of Object_Identifier, Object_Name, Object_Type and Property_List itself,
       which cl. 12.1.1.4.1 leaves out of the list)

Every one of those reads must come back as a ReadProperty-ACK. An Error, Reject or Abort, or no
answer, fails the check: Property_List holds "one property identifier for each property that
exists within the object" (135-2024 cl. 12.1.1.4.1), so a listed property the device cannot read
is a defect, whoever owns it. The reads are sent as raw ReadProperty requests, so a property
bacpypes3 has no datatype for is still read and checked, not skipped.

Exit code 0 = every check passed.
"""
import argparse
import asyncio
import sys

from bacpypes3.apdu import ErrorRejectAbortNack, ReadPropertyACK, ReadPropertyRequest
from bacpypes3.basetypes import PropertyIdentifier
from bacpypes3.primitivedata import ObjectIdentifier

from sc_client import ScClient

DEVICE_INSTANCE = 389022
EXPECTED_OBJECTS = sorted([      # match main.cpp
    ("device", DEVICE_INSTANCE),
    ("analog-input", 1),       # "Bronze"
    ("file", 1),               # "Operational Certificate"
    ("file", 2),               # "Certificate Signing Request"
    ("file", 3),               # "Issuer Certificate Slot 1"
    ("file", 4),               # "Issuer Certificate Slot 2"
    ("network-port", 2),       # the BACnet/SC port - the device's only Network Port
])

# The four properties cl. 12.1.1.4.1 says Property_List does not contain.
NOT_IN_PROPERTY_LIST = ["object-identifier", "object-name", "object-type", "property-list"]

RESULTS = []


def record(name, ok, detail=""):
    ok = bool(ok)
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""), flush=True)
    return ok


def object_key(object_identifier):
    object_type, instance = object_identifier
    return (str(object_type), int(instance))


async def read_raw(client, address, object_identifier, property_identifier, timeout=5.0):
    """One ReadProperty, returned as (ok, outcome text). Never decodes the value."""
    request = ReadPropertyRequest(objectIdentifier=object_identifier,
                                  propertyIdentifier=PropertyIdentifier(property_identifier),
                                  destination=address)
    try:
        response = await asyncio.wait_for(client.app.request(request), timeout)
    except asyncio.TimeoutError:
        return False, "no answer"
    except ErrorRejectAbortNack as error:
        return False, f"{type(error).__name__}: {error}"
    if isinstance(response, ErrorRejectAbortNack):
        return False, f"{type(response).__name__}: {response}"
    if isinstance(response, ReadPropertyACK):
        return True, "value"
    return False, f"unexpected {type(response).__name__}"


async def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--sc-port", type=int, default=4443, help="the example's BACnet/SC port")
    parser.add_argument("--cert-dir", default="certs", help="certificate set with a device (client) certificate")
    args = parser.parse_args()

    async with ScClient(args.sc_port, args.cert_dir, host=args.host) as client:
        address = await client.find_device(DEVICE_INSTANCE)
        record(f"Who-Is: Device {DEVICE_INSTANCE} answers with an I-Am through the hub", address is not None,
               f"VMAC {address}")
        device_id = ObjectIdentifier(("device", DEVICE_INSTANCE))
        object_list = list(await client.app.read_property(address, device_id, "object-list"))
        # Control: the walk below proves nothing if it walks nothing.
        found = sorted(object_key(identifier) for identifier in object_list)
        record("Device Object_List names the Device, Analog Input 1, File 1-4 and Network Port 2",
               found == EXPECTED_OBJECTS, f"{len(found)} objects: {found}")

        reads = 0
        unreadable = []
        for object_identifier in object_list:
            property_list = list(await client.app.read_property(address, object_identifier, "property-list"))
            record(f"{object_identifier}: Property_List reads", property_list, f"{len(property_list)} properties")
            for property_identifier in NOT_IN_PROPERTY_LIST + [str(p) for p in property_list]:
                ok, outcome = await read_raw(client, address, object_identifier, property_identifier)
                reads += 1
                if not ok:
                    unreadable.append(f"{object_identifier} {property_identifier}")
                    print(f"[UNREADABLE] {object_identifier} {property_identifier}: {outcome}", flush=True)
        record(f"every property of every object reads as a value ({reads} reads)", reads and not unreadable,
               f"{len(unreadable)} unreadable: {', '.join(unreadable)}" if unreadable else "")

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if RESULTS and all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
