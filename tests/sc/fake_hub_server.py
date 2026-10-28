#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""
fake_hub_server.py - a fake BACnet/SC hub, to test the hub connector
(--sc-hub-uri / --sc-failover-uri) of BACnetProfileExample-B-SCHUB-CPP.

A mutual-TLS WebSocket server offering the hub.bsc.bacnet.org subprotocol. It
answers a Connect-Request with a Connect-Accept and a Heartbeat-Request with a
Heartbeat-ACK, so the example's hub connector reaches the connected state
without a second real hub. tests/sc/connector_test.py runs it in-process.

WHY THE messageId MUST BE ECHOED: the connector looks up the Connect-Request it
sent by messageId and silently ignores a Connect-Accept that does not echo it,
so a fake hub that answers with a fixed id looks fine in its own log while the
example never reaches the connected state.

IDENTITY: the example uses one certificate for the listener and the connector,
so this script reuses the hub's own certificate and key from --cert-dir as its
server identity (the demo set in certs/ carries serverAuth and clientAuth and a
subjectAltName for 127.0.0.1). It requires the example's client certificate
(mutual TLS, ssl.CERT_REQUIRED against the issuer) and does not check which
leaf was presented: the hub's certificate policy is CA-chain validation only.

USAGE

    pip install -r tests/sc/requirements.txt
    python tests/sc/fake_hub_server.py [--host 127.0.0.1] [--port 47940]
                                        [--cert-dir certs] [--once]

    then, in a separate terminal:

        ./build/BACnetExampleBSCHUB --sc-hub-uri wss://127.0.0.1:47940/

    --once exits after the first connection closes (Ctrl+C works any time).
"""

import argparse
import asyncio
import ssl
import struct
import sys
from pathlib import Path

import cert_paths  # BACnet-named or older certificate file names

try:
    import websockets
except ImportError:
    print("ERROR: the 'websockets' package is required - pip install -r tests/sc/requirements.txt")
    sys.exit(2)

SUBPROTOCOL = "hub.bsc.bacnet.org"

# BVLC-SC function codes (source/BACnetSCBVLL.h) - see hub_listener_test.py's
# identical constants for the ones this script shares with it.
FUNC_CONNECT_REQUEST = 0x06
FUNC_CONNECT_ACCEPT = 0x07
FUNC_HEARTBEAT_REQUEST = 0x0A
FUNC_HEARTBEAT_ACK = 0x0B

# Header option constants (source/BACnetSCHeaderOption.h) - identical to
# hub_listener_test.py's BUILD_CONNECT_REQUEST.
HEADER_OPTION_TYPE_HELLO = 2
HEADER_MARKER_HEADER_DATA_FLAG_BIT = 5

# BVLC control-flag bits (source/BACnetSCBVLL.h).
CONTROL_FLAG_DESTINATION_OPTIONS_BIT = 1

# This fake hub's own identity, reported inside the Connect-Accept payload
# (BACnetSCConnectAccept::SetConnectAccept - VMAC + device UUID). Arbitrary
# but fixed, purely for readability in logs; the example's stack stores these
# (BACnetSCHubConnector_Incoming.cpp's ProcessConnectAccept ->
# websocket->SetConnectionProperties) but this test does not assert on them.
FAKE_HUB_VMAC = bytes([0xFA, 0xCE, 0x00, 0x00, 0x00, 0x01])
FAKE_HUB_UUID = bytes([0xFA, 0xCE, 0xD0, 0x00] + list(range(0x00, 0x0C)))


def build_connect_accept(message_id: int, max_bvlc_length: int = 65535, max_npdu_length: int = 1497) -> bytes:
    """
    Mirrors hub_listener_test.py's build_connect_request byte-for-byte (same
    BACnetSCConnectAccept payload shape as BACnetSCConnectRequest - both are
    VMAC(6) + UUID(16) + maxBVLC(2) + maxNPDU(2), verified against
    BACnetSCConnectAccept::Encode/Decode - see this module's own docstring),
    except: function code 0x07, and message_id MUST be the Connect-Request's
    own messageId (see "WHY THE messageId MUST BE ECHOED" above) - it is a
    required parameter here, never invented, so a caller cannot forget it.
    """
    control_flags = 1 << CONTROL_FLAG_DESTINATION_OPTIONS_BIT  # 0x02 - SetConnectAccept always adds a Hello option too
    header = struct.pack(">BBH", FUNC_CONNECT_ACCEPT, control_flags, message_id)

    hello_capabilities = 0
    hello_marker = (1 << HEADER_MARKER_HEADER_DATA_FLAG_BIT) | HEADER_OPTION_TYPE_HELLO  # 0x22
    hello_option = struct.pack(">BHB", hello_marker, 1, hello_capabilities)

    payload = FAKE_HUB_VMAC + FAKE_HUB_UUID + struct.pack(">HH", max_bvlc_length, max_npdu_length)
    return header + hello_option + payload


def build_heartbeat_ack(message_id: int) -> bytes:
    """
    BACnetSCHeartbeatACK carries no payload beyond the base BVLL header
    (BACnetSCHeartbeatACK.cpp does not override Encode - it has nothing to
    add) and no destination options (control flags 0) - just
    [function][controlFlags][messageId], 4 bytes total.
    """
    return struct.pack(">BBH", FUNC_HEARTBEAT_ACK, 0x00, message_id)


def parse_message_id(frame: bytes) -> int:
    # offset 2..3, big-endian - same layout as hub_listener_test.py's
    # build_connect_request header.
    return struct.unpack(">H", frame[2:4])[0]


def make_server_ssl_context(cert_dir: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # match the listener half's TLS-1.3-only policy
    ctx.load_cert_chain(certfile=str(cert_paths.hub_certificate(cert_dir)),
                        keyfile=str(cert_paths.hub_private_key(cert_dir)))
    ctx.load_verify_locations(cafile=str(cert_paths.issuer_certificate(cert_dir)))
    ctx.verify_mode = ssl.CERT_REQUIRED  # mutual TLS - reject the example if it presents no client cert
    return ctx


async def handle_connection(websocket, once: asyncio.Event):
    peer = websocket.remote_address
    print(f"[fake_hub_server] connection from {peer}, subprotocol={websocket.subprotocol!r}")
    try:
        async for message in websocket:
            if isinstance(message, str):
                print(f"[fake_hub_server] WARNING: got a text frame from {peer} - BACnet/SC forbids this; ignoring")
                continue
            if len(message) < 4:
                print(f"[fake_hub_server] WARNING: frame too short ({len(message)} bytes) from {peer}; ignoring")
                continue

            func = message[0]
            message_id = parse_message_id(message)

            if func == FUNC_CONNECT_REQUEST:
                print(f"[fake_hub_server] Connect-Request received from {peer} "
                      f"(messageId={message_id}, {len(message)} bytes: {message.hex()})")
                reply = build_connect_accept(message_id)
                await websocket.send(reply)
                print(f"[fake_hub_server] Connect-Accept sent to {peer} "
                      f"(messageId={message_id}, {len(reply)} bytes: {reply.hex()})")
            elif func == FUNC_HEARTBEAT_REQUEST:
                print(f"[fake_hub_server] Heartbeat-Request received from {peer} (messageId={message_id})")
                await websocket.send(build_heartbeat_ack(message_id))
                print(f"[fake_hub_server] Heartbeat-ACK sent to {peer} (messageId={message_id})")
            else:
                print(f"[fake_hub_server] unhandled BVLC function 0x{func:02x} from {peer} "
                      f"(messageId={message_id}) - this fixture only answers Connect-Request/Heartbeat-Request")
    except websockets.exceptions.ConnectionClosed as exc:
        print(f"[fake_hub_server] connection from {peer} closed ({exc.code if exc.rcvd else 'abrupt'})")
    finally:
        print(f"[fake_hub_server] connection from {peer} ended")
        once.set()


async def run(host: str, port: int, cert_dir: Path, once: bool, max_seconds: float):
    for needed in (cert_paths.hub_certificate(cert_dir), cert_paths.hub_private_key(cert_dir),
                   cert_paths.issuer_certificate(cert_dir)):
        if not needed.is_file():
            print(f"ERROR: {needed} not found - run: python tools/make_test_certs.py --cert-dir certs")
            return 2

    ssl_ctx = make_server_ssl_context(cert_dir)
    connection_closed = asyncio.Event()

    async def handler(websocket):
        await handle_connection(websocket, connection_closed)

    print(f"[fake_hub_server] listening on wss://{host}:{port}/ (subprotocol \"{SUBPROTOCOL}\", "
          f"TLS 1.3, mutual auth, certs from {cert_dir})")
    async with websockets.serve(handler, host, port, ssl=ssl_ctx, subprotocols=[SUBPROTOCOL]):
        if once:
            try:
                await asyncio.wait_for(connection_closed.wait(), timeout=max_seconds)
            except asyncio.TimeoutError:
                print(f"[fake_hub_server] --once: no connection closed within {max_seconds}s - giving up")
                return 1
            return 0
        # Run until Ctrl+C (or max_seconds, if given, as a safety net for scripted use).
        if max_seconds > 0:
            await asyncio.sleep(max_seconds)
        else:
            await asyncio.Event().wait()
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=47940)
    parser.add_argument("--cert-dir", default="certs")
    parser.add_argument("--once", action="store_true",
                        help="exit as soon as one connection has closed (for scripted use)")
    parser.add_argument("--max-seconds", type=float, default=0,
                        help="safety timeout: exit after this many seconds regardless (0 = run forever "
                             "unless --once, default 0; --once defaults its own wait to 30s if this is 0)")
    args = parser.parse_args()

    max_seconds = args.max_seconds
    if args.once and max_seconds <= 0:
        max_seconds = 30.0

    try:
        return asyncio.run(run(args.host, args.port, Path(args.cert_dir), args.once, max_seconds))
    except KeyboardInterrupt:
        print("\n[fake_hub_server] stopped (Ctrl+C)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
