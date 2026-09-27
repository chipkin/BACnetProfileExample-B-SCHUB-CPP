#!/usr/bin/env python3
"""Segmentation (ANSI/ASHRAE 135 clause 5.2) against the example over BACnet/IP.

The hub claims Segmentation_Supported = segmented-both (the CAS BACnet Stack's
default since 6.x, cas-bacnet-stack#2992). This checks the claim is real:

  1. Device Segmentation_Supported is segmented-both, Max_Segments_Accepted > 1
     and APDU_Segment_Timeout > 0 (cl. 12.11.19-21: both are required when
     segmentation is supported).
  2. Segmented TRANSMIT: this client accepts APDUs of only 128 octets, so the
     hub must segment its ReadPropertyMultiple(Device, ALL) answer. The answer
     must arrive in 2 or more segments and decode.
  3. Segmented RECEIVE: a ReadPropertyMultiple REQUEST longer than the hub's
     1476-octet Max_APDU_Length_Accepted, which this client must segment and
     the hub must reassemble and answer.

Usage (the example running on BACnet/IP port 47870):

    python tests/sc/segmentation_test.py --target 127.0.0.1 --target-port 47870

Exit code 0 = every check passed.
"""
import argparse
import asyncio
import sys

import bacpypes3.appservice as appservice
from bacpypes3.apdu import (
    ErrorRejectAbortNack,
    PropertyReference,
    ReadAccessSpecification,
    ReadPropertyMultipleRequest,
)
from bacpypes3.app import Application
from bacpypes3.argparse import SimpleArgumentParser
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier

# Count the segments this client receives (one append_segment call each) and
# the distinct request segments it sends (get_segment, by sequence number).
SEGMENTS_RECEIVED = 0
REQUEST_SEGMENTS_SENT = set()
_append_segment = appservice.ClientSSM.append_segment
_get_segment = appservice.ClientSSM.get_segment


def _counting_append_segment(self, apdu):
    global SEGMENTS_RECEIVED
    SEGMENTS_RECEIVED += 1
    return _append_segment(self, apdu)


def _counting_get_segment(self, indx):
    if self.segmentCount and self.segmentCount > 1:
        REQUEST_SEGMENTS_SENT.add(indx)
    return _get_segment(self, indx)


appservice.ClientSSM.append_segment = _counting_append_segment
appservice.ClientSSM.get_segment = _counting_get_segment


async def main():
    parser = SimpleArgumentParser()
    parser.set_defaults(address="127.0.0.1/32:47818")
    parser.add_argument("--target", default="127.0.0.1", help="the example's BACnet/IP address")
    parser.add_argument("--target-port", type=int, default=47808, help="the example's BACnet/IP port")
    parser.add_argument("--device-instance", type=int, default=389022, help="the example's device instance")
    args = parser.parse_args()

    device = Address(f"{args.target}:{args.target_port}")
    device_id = ObjectIdentifier(f"device,{args.device_instance}")
    app = Application.from_args(args)
    # This client: segmented-both, up to 64 segments.
    app.device_object.segmentationSupported = "segmented-both"
    app.device_object.maxSegmentsAccepted = 64

    results = []

    def check(ok, what, detail=""):
        results.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}: {what}" + (f" - {detail}" if detail else ""))

    global SEGMENTS_RECEIVED
    try:
        # 1. The claim.
        seg = await app.read_property(device, device_id, "segmentation-supported")
        check(str(seg) == "segmented-both", "Segmentation_Supported is segmented-both", str(seg))
        max_segs = await app.read_property(device, device_id, "max-segments-accepted")
        check(int(max_segs) > 1, "Max_Segments_Accepted > 1", str(max_segs))
        timeout = await app.read_property(device, device_id, "apdu-segment-timeout")
        check(int(timeout) > 0, "APDU_Segment_Timeout > 0", f"{timeout} ms")

        # 2. Segmented transmit: this client accepts only 128-octet APDUs.
        app.device_object.maxApduLengthAccepted = 128
        SEGMENTS_RECEIVED = 0
        request = ReadPropertyMultipleRequest(
            listOfReadAccessSpecs=[ReadAccessSpecification(
                objectIdentifier=device_id,
                listOfPropertyReferences=[PropertyReference(propertyIdentifier="all")])],
            destination=device)
        try:
            ack = await app.request(request)
            count = len(ack.listOfReadAccessResults[0].listOfResults)
            check(SEGMENTS_RECEIVED >= 2, "RPM(Device, ALL) answer arrives segmented at a 128-octet max APDU",
                  f"{SEGMENTS_RECEIVED} segments, {count} properties")
        except ErrorRejectAbortNack as err:
            check(False, "RPM(Device, ALL) answer arrives segmented at a 128-octet max APDU", repr(err))

        # 3. Segmented receive: a request longer than the hub's 1476-octet max APDU.
        app.device_object.maxApduLengthAccepted = 1476
        SEGMENTS_RECEIVED = 0
        REQUEST_SEGMENTS_SENT.clear()
        # About 2 octets per reference, so 1000 references is ~2000 octets.
        refs = [PropertyReference(propertyIdentifier=p)
                for p in ("object-name", "object-type", "object-identifier", "description")] * 250
        request = ReadPropertyMultipleRequest(
            listOfReadAccessSpecs=[ReadAccessSpecification(objectIdentifier=device_id,
                                                           listOfPropertyReferences=refs)],
            destination=device)
        try:
            ack = await app.request(request)
            count = len(ack.listOfReadAccessResults[0].listOfResults)
            check(len(REQUEST_SEGMENTS_SENT) >= 2, "the RPM request is sent segmented (longer than the hub's 1476-octet max APDU)",
                  f"{len(refs)} references in {len(REQUEST_SEGMENTS_SENT)} request segments")
            check(count == len(refs), "hub reassembles the segmented request and answers every reference",
                  f"{count} results, answer in {SEGMENTS_RECEIVED} segments")
        except ErrorRejectAbortNack as err:
            check(False, "hub reassembles a segmented RPM request (> 1476 octets) and answers every reference", repr(err))
    finally:
        app.close()

    passed = sum(1 for r in results if r)
    print(f"\n{passed}/{len(results)} checks passed.")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
