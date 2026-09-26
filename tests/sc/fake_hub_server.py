#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""
fake_hub_server.py - V4 verification fixture for the BACnet/SC hub CONNECTOR
(sc_transport/ScTransport.h's Connect()/Disconnect(), Phase 3) in
BACnetProfileExample-B-SCHUB-CPP.

Per docs/bacnet-sc-transport-plan.md's "Verification" section, V4:

    run the example with --sc-hub-uri wss://127.0.0.1:<port>/, pointed at
    THIS script; assert the example dials out, presents its own client
    certificate (mutual TLS), and sends a binary BVLC-SC Connect-Request
    (function 0x06); answer with a canned Connect-Accept (function 0x07,
    echoing the Connect-Request's messageId - see WHY THE messageId MUST BE
    ECHOED below) and confirm the example's own console shows a connected
    state (BACnetStack_SetBACnetSCWebSocketStatus(..., Connected) via
    CallbackBACnetSCStateChange, or a later Heartbeat-Request). Then kill this
    script (Ctrl+C, or let --once exit it) and confirm the example logs
    Disconnected, and that the STACK - not ScTransport - re-dials after its
    own retry timeout (this script does not assert that part; it has no
    handle on the example's own process - same limitation
    hub_listener_test.py's V2 documents for its "peer eviction" half. See the
    plan's V4 for the exact wording and RUN_MANUALLY_AND_CHECK_LOG below).

WHY THE messageId MUST BE ECHOED (not just "any valid Connect-Accept"):
    submodules/cas-bacnet-stack/source/BACnetSCHubConnector_Incoming.cpp's
    ProcessConnectAccept() looks up the ORIGINAL Connect-Request the connector
    itself sent by messageId (this->m_sentMessages.FindById(messageId)) and
    silently ignores ("no sent message with messageId=..., ignore") a
    Connect-Accept that does not echo it back exactly - the same behaviour a
    real hub's BACnetSCHubFunctionManager.cpp implements
    (SendControlMessage(..., scBvll->GetMessageId(), ...)). A fake hub that
    sends back a fixed/wrong messageId would look, from this script's own
    log, like it worked (a Connect-Accept frame really did go out) while the
    example's own stack quietly dropped it and never reached Connected - this
    is a genuine gotcha, not a hypothetical one, found by reading that source
    file rather than guessing at the wire format (same derivation approach as
    hub_listener_test.py's BUILD_CONNECT_REQUEST docstring for V2).

WHY THIS SCRIPT REUSES certs/hub.crt + certs/hub.key AS ITS OWN IDENTITY:
    The example's Configure() call (main.cpp) uses the SAME certificate/key
    pair (--sc-cert-dir's hub.crt/hub.key) for BOTH the listener and connector
    roles - one BACnet/SC device, one identity, per ScTransport.h's
    class-header comment. This script stands in for a DIFFERENT device (a
    real hub), but for a lab test signed by the same throwaway CA
    (BACnetExampleBSCHUB --generate-certs), reusing hub.crt/hub.key as this
    fake hub's own server identity is sufficient: it already carries EKU
    serverAuth+clientAuth and a SAN covering 127.0.0.1/localhost, and the
    example's own Connect() sets LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK (the
    CA chain is still fully verified - see ScTransport.cpp's Connect() for
    why). This script REQUIRES the example's client certificate in turn
    (mutual TLS, ssl.CERT_REQUIRED against ca.crt) - it does not validate
    which specific leaf certificate was presented (this app's own cert policy
    is CA-chain-only, plan open risk #6 - this test fixture matches that,
    it does not go further).

USAGE

    pip install -r tests/sc/requirements.txt
    BACnetExampleBSCHUB --generate-certs          # once, if certs/ is empty
    python tests/sc/fake_hub_server.py [--host 127.0.0.1] [--port 47820]
                                        [--cert-dir certs] [--once]

    Then, in a separate terminal, point the example at it:

        ./build/BACnetExampleBSCHUB.exe --sc-hub-uri wss://127.0.0.1:47820/ \\
            --sc-cert-dir ./certs

    Watch THIS script's own stdout for "Connect-Request received" /
    "Connect-Accept sent", and the EXAMPLE's stdout for
    "BACnet/SC: connected to hub" / a CallbackBACnetSCStateChange line showing
    a connected state. --once exits this script after the first connection
    closes (Ctrl+C works too, any time).
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
            print(f"ERROR: {needed} not found - run: BACnetExampleBSCHUB --generate-certs")
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
    parser.add_argument("--port", type=int, default=47820)
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
