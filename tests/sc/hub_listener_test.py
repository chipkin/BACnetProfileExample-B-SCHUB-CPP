#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""
hub_listener_test.py - V1/V2 verification for the BACnet/SC hub listener
(sc_transport/ScTransport.h) in BACnetProfileExample-B-SCHUB-CPP.

Per docs/bacnet-sc-transport-plan.md's "Verification" section:

  V1 (TLS/WS handshake): connect with the node test-peer certificate
     (certs/node.crt + node.key, signed by certs/ca.crt - see
     BACnetExampleBSCHUB --generate-certs) and assert:
       - TLS 1.3 is negotiated,
       - the server echoes back the "hub.bsc.bacnet.org" subprotocol
         (135-2024 AB.7.1 - NOT plugfest-example's "hub.bacnet.org", which is
         confirmed wrong - see the plan's fact 1).
     Negative cases:
       - no client certificate -> the TLS handshake itself is refused
         (mutual TLS is required - LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT),
       - TLS 1.2 -> refused (the listener only offers TLS 1.3),
       - a wrong subprotocol name -> the WebSocket upgrade is refused with
         HTTP 400 (not a dropped connection),
       - a text frame on an otherwise-good connection -> the server closes
         with WebSocket close code 1003 (Unacceptable Opcode) - BACnet/SC is
         binary-framed only.

  V2 (protocol through the listener): hand-build a BVLC-SC Connect-Request
     (function code 0x06) on the wire - see BUILD_CONNECT_REQUEST below for
     the exact byte layout, verified against
     submodules/cas-bacnet-stack/source/BACnetSCConnectRequest.cpp,
     BACnetSCBVLL.cpp and BACnetSCHeaderOption.cpp (a Connect-Request always
     carries a mandatory Hello destination option per
     BACnetSCHubConnectorHelpers::EnsureHelloDestinationOption - not
     documented in the SC manual's own worked examples, which is why this is
     derived from source rather than copied from a spec listing) - and assert
     a Connect-Accept (function code 0x07) comes back on the same socket.
     Then the test closes the connection abruptly (no WS close handshake) and
     the example's own log is expected to show a "disconnected" / peer
     eviction message (status 3 = Disconnected, BACnetSCConstants.h) - see
     RUN_MANUALLY_AND_CHECK_LOG below for how that half is verified (this
     script cannot read the example's stdout when the example is not started
     by this script - see the "USAGE" section).

USAGE

    Start the example first (a separate process/terminal), pointed at the
    same certs/ this script uses:

        BACnetExampleBSCHUB.exe --sc-port 47819 --sc-cert-dir ./certs

    Then, from the repository root:

        pip install -r tests/sc/requirements.txt
        python tests/sc/hub_listener_test.py [--host 127.0.0.1] [--port 47819]
                                              [--cert-dir certs]

    Exit code 0 = every check passed. Non-zero = at least one failed (see
    stdout for which).
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
    from websockets.exceptions import InvalidHandshake, ConnectionClosed
except ImportError:
    print("ERROR: the 'websockets' package is required - pip install -r tests/sc/requirements.txt")
    sys.exit(2)

SUBPROTOCOL = "hub.bsc.bacnet.org"
WRONG_SUBPROTOCOL = "hub.bacnet.org"  # plan fact 1 - the one plugfest-example wrongly used

# BVLC-SC function codes (source/BACnetSCBVLL.h).
FUNC_CONNECT_REQUEST = 0x06
FUNC_CONNECT_ACCEPT = 0x07

# Header option constants (source/BACnetSCHeaderOption.h).
HEADER_OPTION_TYPE_HELLO = 2
HEADER_MARKER_HEADER_DATA_FLAG_BIT = 5  # bit 5 set -> header carries data

# BVLC control-flag bits (source/BACnetSCBVLL.h).
CONTROL_FLAG_DESTINATION_OPTIONS_BIT = 1

RESULTS = []  # (name, passed: bool, detail: str)


def record(name, passed, detail=""):
    RESULTS.append((name, passed, detail))
    print(f"{'PASS' if passed else 'FAIL'}: {name}" + (f" - {detail}" if detail else ""))


def build_connect_request(vmac: bytes, device_uuid: bytes, message_id: int,
                          max_bvlc_length: int = 65535, max_npdu_length: int = 1497) -> bytes:
    """
    Hand-builds a BVLC-SC Connect-Request frame byte-for-byte, matching
    BACnetSCConnectRequest::Encode / BACnetSCBVLL::Encode /
    BACnetSCHeaderOption::Encode in the CAS BACnet Stack source (see the
    module docstring for exact file citations). Layout:

        offset 0      : bvlcFunction        = 0x06 (ConnectRequest)
        offset 1      : controlFlags        = 0x02 (destination-options bit set -
                                                      SetConnectRequest() always adds
                                                      a Hello destination option)
        offset 2..3   : messageId            (big-endian uint16)
        -- destination options (HasDestinationOptions()==true) --
        offset 4      : Hello option headerMarker = 0x22
                          (bit7 More-Options=0 [last/only option],
                           bit6 Must-Understand=0,
                           bit5 Header-Data-Flag=1,
                           bits0-4 headerOptionType=2 [Hello])
        offset 5..6   : Hello option headerLength  = 0x0001 (big-endian uint16)
        offset 7      : Hello option headerData    = capabilities byte (0 - no
                                                      "identity relay" bit set)
        -- ConnectRequest payload (BACnetSCConnectRequest::CONNECT_REQUEST_PAYLOAD_SIZE) --
        offset 8..13  : VMAC address              (6 bytes)
        offset 14..29 : Device UUID               (16 bytes)
        offset 30..31 : Maximum BVLC length         (big-endian uint16)
        offset 32..33 : Maximum NPDU length         (big-endian uint16)

    Total 34 bytes for this (no origin/destination VMAC on the wire - this is
    a fresh, not-yet-connected socket, matching every ConnectHubFunctionPeer()
    call in the stack's own unit tests, e.g.
    tests/BACnetSC_Tests/TestBACnetInterface_BACnetSC.cpp).
    """
    assert len(vmac) == 6
    assert len(device_uuid) == 16

    control_flags = 1 << CONTROL_FLAG_DESTINATION_OPTIONS_BIT  # 0x02
    header = struct.pack(">BBH", FUNC_CONNECT_REQUEST, control_flags, message_id)

    hello_capabilities = 0
    hello_marker = (1 << HEADER_MARKER_HEADER_DATA_FLAG_BIT) | HEADER_OPTION_TYPE_HELLO  # 0x22
    hello_option = struct.pack(">BHB", hello_marker, 1, hello_capabilities)

    payload = vmac + device_uuid + struct.pack(">HH", max_bvlc_length, max_npdu_length)

    return header + hello_option + payload


def parse_bvlc_function(frame: bytes) -> int:
    if len(frame) < 1:
        raise ValueError("empty frame")
    return frame[0]


# Client certificate label (file stem) - set from --client-cert in main().
CLIENT_CERT = "node"


def make_ssl_context(cert_dir: Path, use_client_cert: bool, min_version=None, max_version=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # lab test CA is not in the system trust store
    if use_client_cert:
        certfile, keyfile = cert_paths.client_files(cert_dir, CLIENT_CERT)
        ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    if min_version is not None:
        ctx.minimum_version = min_version
    if max_version is not None:
        ctx.maximum_version = max_version
    return ctx


async def v1_positive(uri: str, cert_dir: Path):
    """TLS 1.3 negotiates, subprotocol is echoed back."""
    ctx = make_ssl_context(cert_dir, use_client_cert=True)
    try:
        async with websockets.connect(uri, ssl=ctx, subprotocols=[SUBPROTOCOL],
                                      open_timeout=5) as ws:
            tls_version = ws.transport.get_extra_info("ssl_object").version()
            record("V1 positive: TLS version is TLSv1.3", tls_version == "TLSv1.3", tls_version)
            record("V1 positive: subprotocol echoed", ws.subprotocol == SUBPROTOCOL, ws.subprotocol)
            return ws.subprotocol == SUBPROTOCOL and tls_version == "TLSv1.3"
    except Exception as exc:
        record("V1 positive: TLS 1.3 handshake + subprotocol echo", False, f"{type(exc).__name__}: {exc}")
        return False


async def v1_no_client_cert(uri: str, cert_dir: Path):
    ctx = make_ssl_context(cert_dir, use_client_cert=False)
    try:
        async with websockets.connect(uri, ssl=ctx, subprotocols=[SUBPROTOCOL], open_timeout=5):
            record("V1 negative: no client cert -> refused", False, "connection unexpectedly succeeded")
            return False
    except Exception as exc:
        record("V1 negative: no client cert -> refused", True, f"{type(exc).__name__}: {exc}")
        return True


async def v1_tls12_only(uri: str, cert_dir: Path):
    ctx = make_ssl_context(cert_dir, use_client_cert=True,
                           min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2)
    try:
        async with websockets.connect(uri, ssl=ctx, subprotocols=[SUBPROTOCOL], open_timeout=5):
            record("V1 negative: TLS 1.2 -> refused", False, "connection unexpectedly succeeded")
            return False
    except Exception as exc:
        record("V1 negative: TLS 1.2 -> refused", True, f"{type(exc).__name__}: {exc}")
        return True


async def v1_wrong_subprotocol(uri: str, cert_dir: Path):
    ctx = make_ssl_context(cert_dir, use_client_cert=True)
    try:
        async with websockets.connect(uri, ssl=ctx, subprotocols=[WRONG_SUBPROTOCOL], open_timeout=5) as ws:
            # If lws let the upgrade through anyway, it must NOT have accepted
            # the wrong name as the negotiated subprotocol.
            ok = ws.subprotocol != WRONG_SUBPROTOCOL
            record("V1 negative: wrong subprotocol -> rejected", ok,
                   f"negotiated={ws.subprotocol!r} (connection stayed open - should have been rejected)")
            return ok
    except Exception as exc:
        # The hub answers an unknown subprotocol with HTTP 400 (issue #27),
        # not a dropped TCP connection - check for that status specifically.
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
        ok = status == 400
        record("V1 negative: wrong subprotocol -> HTTP 400", ok, f"{type(exc).__name__}: {exc}")
        return ok


async def v1_text_frame_closes_1003(uri: str, cert_dir: Path):
    ctx = make_ssl_context(cert_dir, use_client_cert=True)
    try:
        async with websockets.connect(uri, ssl=ctx, subprotocols=[SUBPROTOCOL], open_timeout=5) as ws:
            await ws.send("this is a text frame, not binary - BACnet/SC forbids it")
            try:
                await asyncio.wait_for(ws.recv(), timeout=5)
                record("V1 negative: text frame -> closed 1003", False, "connection did not close")
                return False
            except ConnectionClosed as cc:
                ok = cc.rcvd is not None and cc.rcvd.code == 1003
                record("V1 negative: text frame -> closed 1003", ok,
                       f"close code={cc.rcvd.code if cc.rcvd else None}")
                return ok
    except Exception as exc:
        record("V1 negative: text frame -> closed 1003", False, f"{type(exc).__name__}: {exc}")
        return False


async def v2_connect_request_gets_accept(uri: str, cert_dir: Path):
    """Hand-build a Connect-Request, assert a Connect-Accept comes back, then
    close abruptly (the example's own log is expected to show the peer
    eviction - see the module docstring; not asserted here, this script has
    no handle on a separately-started example process's stdout)."""
    ctx = make_ssl_context(cert_dir, use_client_cert=True)
    vmac = bytes([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
    device_uuid = bytes(range(0x50, 0x60))
    request = build_connect_request(vmac, device_uuid, message_id=4242)

    try:
        async with websockets.connect(uri, ssl=ctx, subprotocols=[SUBPROTOCOL], open_timeout=5) as ws:
            await ws.send(request)
            reply = await asyncio.wait_for(ws.recv(), timeout=5)
            if isinstance(reply, str):
                record("V2: Connect-Request -> Connect-Accept", False, "got a text frame back, expected binary")
                return False
            func = parse_bvlc_function(reply)
            ok = func == FUNC_CONNECT_ACCEPT
            record("V2: Connect-Request -> Connect-Accept", ok,
                   f"got BVLC function 0x{func:02x} (wanted 0x{FUNC_CONNECT_ACCEPT:02x}), "
                   f"{len(reply)} bytes: {reply.hex()}")
            # Abrupt close (no WS close handshake) - exercises the example's
            # LWS_CALLBACK_CLOSED path without a prior WS_PEER_INITIATED_CLOSE,
            # same as ScTransport.cpp's Disconnected(3) default. Check the
            # example's own stdout for the eviction log line (see module
            # docstring "USAGE").
            ws.transport.close()
            return ok
    except Exception as exc:
        record("V2: Connect-Request -> Connect-Accept", False, f"{type(exc).__name__}: {exc}")
        return False


async def v2_connect_request_without_hello_refused(uri: str, cert_dir: Path):
    """A Connect-Request WITHOUT the Hello destination option - what YABE sends
    (issue #40) - gets a BVLC-Result NAK: the hub follows 135-2024 AB.2.2
    strictly. (cas-bacnet-stack#3097 asks for a flag to relax this; until the
    hub offers it, refusal is the expected answer.) The NAK carries the
    stack's reason, which the hub also logs."""
    ctx = make_ssl_context(cert_dir, use_client_cert=True)
    vmac = bytes([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x1F])
    device_uuid = bytes(range(0x60, 0x70))
    payload = vmac + device_uuid + struct.pack(">HH", 65535, 1497)
    request = struct.pack(">BBH", FUNC_CONNECT_REQUEST, 0x00, 4243) + payload  # no destination options
    name = "V2: Connect-Request without Hello -> BVLC-Result NAK"
    try:
        async with websockets.connect(uri, ssl=ctx, subprotocols=[SUBPROTOCOL], open_timeout=5) as ws:
            await ws.send(request)
            reply = await asyncio.wait_for(ws.recv(), timeout=5)
            ok = isinstance(reply, bytes) and len(reply) >= 6 and reply[0] == 0x00 and reply[5] == 0x01
            details = reply[11:].decode("utf-8", "replace") if ok and len(reply) > 11 else ""
            record(name, ok, f"{len(reply)} bytes: {reply.hex()}" + (f' - "{details}"' if details else ""))
            return ok
    except Exception as exc:
        record(name, False, f"{type(exc).__name__}: {exc}")
        return False


async def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=47819)
    parser.add_argument("--cert-dir", default="certs")
    parser.add_argument("--client-cert", default=None,
                        help="client certificate label to connect with, e.g. client-02 "
                             "(clients/client-02/ from BACnetExampleBSCHUB --generate-certs). "
                             "Default: node (BACnetExampleBSCHUB --generate-certs) if present, else client-01.")
    args = parser.parse_args()

    global CLIENT_CERT
    cert_dir = Path(args.cert_dir)
    CLIENT_CERT = args.client_cert or cert_paths.default_client_label(cert_dir)
    certfile, keyfile = cert_paths.client_files(cert_dir, CLIENT_CERT)
    for needed in (certfile, keyfile, cert_paths.issuer_certificate(cert_dir)):
        if not needed.is_file():
            print(f"ERROR: {needed} not found - run: BACnetExampleBSCHUB --generate-certs")
            return 2
    print(f"Using client certificate {certfile}")

    uri = f"wss://{args.host}:{args.port}/"
    print(f"Testing BACnet/SC hub listener at {uri} (certs in {cert_dir})\n")

    await v1_positive(uri, cert_dir)
    await v1_no_client_cert(uri, cert_dir)
    await v1_tls12_only(uri, cert_dir)
    await v1_wrong_subprotocol(uri, cert_dir)
    await v1_text_frame_closes_1003(uri, cert_dir)
    await v2_connect_request_gets_accept(uri, cert_dir)
    await v2_connect_request_without_hello_refused(uri, cert_dir)

    print()
    failed = [name for name, passed, _ in RESULTS if not passed]
    print(f"{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed.")
    if failed:
        print("FAILED: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
