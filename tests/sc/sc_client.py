#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""A BACnet client over BACnet/SC, for the tests that read and write the hub.

The example has no BACnet/IP port, so every BACnet test talks to it the way a
real BACnet/SC device does: it connects to the hub function (WebSocket + TLS 1.3
with a device certificate, subprotocol hub.bsc.bacnet.org), sends a
Connect-Request, and then exchanges BVLC-SC Encapsulated-NPDU messages
(ANSI/ASHRAE 135-2024 Annex AB) through the hub.

The BACnet application layer above that - APDU encoding, confirmed requests,
segmentation - is bacpypes3's ordinary Application. Only the data link is
new: ScLink below is a bacpypes3 link layer that carries NPDUs over the hub
connection instead of UDP. Addresses on this link are BACnet/SC VMACs
(6-octet LocalStation addresses).

    async with ScClient(port=4443, cert_dir="certs") as client:
        hub = await client.find_device(389022)      # Who-Is/I-Am, through the hub
        name = await client.app.read_property(hub, ObjectIdentifier("device,389022"), "object-name")

The hub's own device answers on the hub function: a request sent to the VMAC
its I-Am came from reaches it. find_device() learns that VMAC with a
broadcast Who-Is.
"""
import asyncio
import os
import struct
import sys
from pathlib import Path

import websockets

from bacpypes3.app import Application
from bacpypes3.comm import Server
from bacpypes3.local.device import DeviceObject
from bacpypes3.pdu import PDU, Address, LocalStation

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hub_listener_test as listener  # noqa: E402 - Connect-Request builder and TLS context

# BVLC-SC function codes and control flags (ANSI/ASHRAE 135-2024 AB.2).
FUNC_RESULT = 0x00
FUNC_ENCAPSULATED_NPDU = 0x01
FUNC_CONNECT_ACCEPT = 0x07
FUNC_DISCONNECT_REQUEST = 0x08
FUNC_DISCONNECT_ACK = 0x09
FUNC_HEARTBEAT_REQUEST = 0x0A
FUNC_HEARTBEAT_ACK = 0x0B
FLAG_ORIGINATING_VMAC = 0x08
FLAG_DESTINATION_VMAC = 0x04
FLAG_DESTINATION_OPTIONS = 0x02
FLAG_DATA_OPTIONS = 0x01
BROADCAST_VMAC = b"\xff" * 6


def _skip_header_options(frame, offset):
    """Skips a list of BVLC-SC header options; returns the offset after it."""
    while True:
        marker = frame[offset]
        offset += 1
        if marker & 0x20:  # Header Data Flag: a 2-octet length and the data follow
            (length,) = struct.unpack_from(">H", frame, offset)
            offset += 2 + length
        if not marker & 0x80:  # More Options flag clear: that was the last one
            return offset


def parse_bvlc(frame):
    """(function, message_id, originating VMAC or None, destination VMAC or None, payload)."""
    function, flags, message_id = struct.unpack_from(">BBH", frame, 0)
    offset = 4
    origin = destination = None
    if flags & FLAG_ORIGINATING_VMAC:
        origin = bytes(frame[offset:offset + 6])
        offset += 6
    if flags & FLAG_DESTINATION_VMAC:
        destination = bytes(frame[offset:offset + 6])
        offset += 6
    if flags & FLAG_DESTINATION_OPTIONS:
        offset = _skip_header_options(frame, offset)
    if flags & FLAG_DATA_OPTIONS:
        offset = _skip_header_options(frame, offset)
    return function, message_id, origin, destination, bytes(frame[offset:])


class ScLink(Server[PDU]):
    """A bacpypes3 link layer over one hub connection: NPDUs go out as
    Encapsulated-NPDU messages addressed to a VMAC (or the broadcast VMAC), and
    every Encapsulated-NPDU the hub relays to us comes back up."""

    def __init__(self, ws, vmac):
        Server.__init__(self)
        self.ws = ws
        self.vmac = vmac
        self.message_id = 1
        self.reader = asyncio.ensure_future(self._read_loop())

    def _next_message_id(self):
        self.message_id = (self.message_id + 1) & 0xFFFF
        return self.message_id

    async def indication(self, pdu):
        destination = pdu.pduDestination
        if destination.addrType == Address.localBroadcastAddr:
            vmac = BROADCAST_VMAC
        else:
            vmac = bytes(destination.addrAddr)
        frame = struct.pack(">BBH", FUNC_ENCAPSULATED_NPDU, FLAG_DESTINATION_VMAC, self._next_message_id())
        await self.ws.send(frame + vmac + bytes(pdu.pduData))

    async def _read_loop(self):
        try:
            async for frame in self.ws:
                if isinstance(frame, str):
                    continue
                function, message_id, origin, _destination, payload = parse_bvlc(frame)
                if function == FUNC_HEARTBEAT_REQUEST:
                    await self.ws.send(struct.pack(">BBH", FUNC_HEARTBEAT_ACK, 0, message_id))
                elif function == FUNC_DISCONNECT_REQUEST:
                    await self.ws.send(struct.pack(">BBH", FUNC_DISCONNECT_ACK, 0, message_id))
                elif function == FUNC_ENCAPSULATED_NPDU and origin is not None:
                    await self.response(PDU(payload, source=LocalStation(origin),
                                            destination=LocalStation(self.vmac)))
        except websockets.exceptions.ConnectionClosed:
            pass

    def close(self):
        self.reader.cancel()


class ScClient:
    """Connects to the hub as one BACnet/SC device and runs a bacpypes3
    Application on that connection (app). Use as an async context manager."""

    def __init__(self, port, cert_dir, host="127.0.0.1", client_cert=None, instance=None,
                 max_apdu=1476, segmentation="segmented-both", max_segments=64):
        self.uri = f"wss://{host}:{port}/"
        self.cert_dir = Path(cert_dir)
        self.client_cert = client_cert
        # A random VMAC (locally administered, unicast) and UUID, so test
        # scripts never collide with each other on one hub.
        self.vmac = bytes([0x02]) + os.urandom(5)
        self.uuid = os.urandom(16)
        self.instance = instance if instance is not None else 3_000_000 + int.from_bytes(os.urandom(2), "big")
        self.max_apdu = max_apdu
        self.segmentation = segmentation
        self.max_segments = max_segments
        self.ws = None
        self.link = None
        self.app = None

    async def __aenter__(self):
        if self.client_cert:
            listener.CLIENT_CERT = self.client_cert
        else:
            import cert_paths
            listener.CLIENT_CERT = cert_paths.default_client_label(self.cert_dir)
        ctx = listener.make_ssl_context(self.cert_dir, use_client_cert=True)
        self.ws = await websockets.connect(self.uri, ssl=ctx, subprotocols=[listener.SUBPROTOCOL],
                                           open_timeout=10, max_size=None)
        await self.ws.send(listener.build_connect_request(self.vmac, self.uuid, message_id=1))
        reply = await asyncio.wait_for(self.ws.recv(), timeout=10)
        if not isinstance(reply, bytes) or reply[0] != FUNC_CONNECT_ACCEPT:
            await self.ws.close()
            raise RuntimeError(f"the hub did not accept the Connect-Request: {reply!r}")

        device = DeviceObject(
            objectIdentifier=("device", self.instance),
            objectName=f"BACnet/SC test client {self.instance}",
            vendorIdentifier=999,
            maxApduLengthAccepted=self.max_apdu,
            segmentationSupported=self.segmentation,
            maxSegmentsAccepted=self.max_segments,
        )
        self.app = Application.from_object_list([device])
        self.link = ScLink(self.ws, self.vmac)
        self.app.nsap.bind(self.link, address=LocalStation(self.vmac))
        self.app.link_layers[device.objectIdentifier] = self.link
        return self

    async def __aexit__(self, *exc):
        if self.app is not None:
            self.app.close()
        if self.ws is not None:
            self.ws.transport.close()
        return False

    async def find_device(self, instance, timeout=5.0):
        """Who-Is for one device instance, broadcast through the hub. Returns
        the address (VMAC) its I-Am came from."""
        i_ams = await self.app.who_is(instance, instance, timeout=timeout)
        if not i_ams:
            raise RuntimeError(f"no I-Am from device {instance} through the hub")
        return i_ams[0].pduSource
