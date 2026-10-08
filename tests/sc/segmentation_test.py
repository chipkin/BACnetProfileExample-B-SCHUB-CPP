#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""Segmentation (ANSI/ASHRAE 135 clause 5.2) against the example over BACnet/SC.

The hub claims Segmentation_Supported = segmented-both (the CAS BACnet Stack's
default since 6.x, cas-bacnet-stack#2992). This checks the claim is real,
connected to the hub as a BACnet/SC device (sc_client.py):

  1. Device Segmentation_Supported is segmented-both, Max_Segments_Accepted > 1
     and APDU_Segment_Timeout > 0 (cl. 12.11.19-21: both are required when
     segmentation is supported).
  2. Segmented TRANSMIT: this client accepts APDUs of only 128 octets, so the
     hub must segment its ReadPropertyMultiple(Device, ALL) answer. The answer
     must arrive in 2 or more segments and decode.
  3. Segmented RECEIVE: a ReadPropertyMultiple REQUEST longer than the hub's
     1476-octet Max_APDU_Length_Accepted, which this client must segment and
     the hub must reassemble and answer.

Usage (the example running with --sc-port 4443 on the demo certificates):

    python tests/sc/segmentation_test.py --sc-port 4443 --cert-dir certs

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
from bacpypes3.primitivedata import ObjectIdentifier

from sc_client import ScClient

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
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--sc-port", type=int, default=4443, help="the example's BACnet/SC port")
    parser.add_argument("--cert-dir", default="certs", help="certificate set with a device (client) certificate")
    parser.add_argument("--device-instance", type=int, default=389022, help="the example's device instance")
    args = parser.parse_args()

    results = []

    def check(ok, what, detail=""):
        results.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}: {what}" + (f" - {detail}" if detail else ""))

    global SEGMENTS_RECEIVED
    # This client: segmented-both, up to 64 segments.
    async with ScClient(args.sc_port, args.cert_dir, host=args.host, segmentation="segmented-both",
                        max_segments=64) as client:
        app = client.app
        device = await client.find_device(args.device_instance)
        device_id = ObjectIdentifier(f"device,{args.device_instance}")

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
            check(len(REQUEST_SEGMENTS_SENT) >= 2,
                  "the RPM request is sent segmented (longer than the hub's 1476-octet max APDU)",
                  f"{len(refs)} references in {len(REQUEST_SEGMENTS_SENT)} request segments")
            check(count == len(refs), "hub reassembles the segmented request and answers every reference",
                  f"{count} results, answer in {SEGMENTS_RECEIVED} segments")
        except ErrorRejectAbortNack as err:
            check(False, "hub reassembles a segmented RPM request (> 1476 octets) and answers every reference",
                  repr(err))

    passed = sum(1 for r in results if r)
    print(f"\n{passed}/{len(results)} checks passed.")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
