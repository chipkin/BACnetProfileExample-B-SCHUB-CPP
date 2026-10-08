# `sc_transport/` - the BACnet/SC WebSocket+TLS transport

This folder is the WebSocket+TLS transport underneath this example's
BACnet/SC hub function (NM-SCH-B) - see the top of `../main.cpp` for how it
fits into the whole device. This document is the
**wire-level contract**: what a caller (`main.cpp`) needs to know to drive
`ScTransport` correctly, without re-deriving it from the source.

See `ScTransport.h` and `ScTransportRouter.h`'s own header comments for the
full design rationale; this file is the summary.

## Two classes, two jobs

- **`ScTransport`** - owns the listener's libwebsockets `lws_context` and
  speaks WebSocket+TLS. It
  knows nothing about BACnet or the CAS BACnet Stack's C API.
- **`ScTransportRouter`** - the glue: registers the stack's
  `ReceiveMessageForPort`/`SendMessageForPort` callbacks, moves the BACnet/SC
  Network Port's messages to and from `ScTransport` (the example has no
  BACnet/IP port), and drains `ScTransport`'s status-event queue into
  `BACnetStack_SetBACnetSCWebSocketStatus`.

## The facts that make this correct (not obvious from the stack's own docs)

These are load-bearing details established by reading the stack's source,
not its (partly wrong - see
[cas-bacnet-stack#3094](https://github.com/chipkin/cas-bacnet-stack/issues/3094))
manual. After a stack update, re-verify every one of these against
`submodules/cas-bacnet-stack/source/`.

1. **Subprotocol is `hub.bsc.bacnet.org`** (135-2024 AB.7.1) - not
   `hub.bacnet.org`, which some older code used and which is wrong. A request for any other subprotocol is refused
   with HTTP 400 at `LWS_CALLBACK_HTTP_CONFIRM_UPGRADE`, before lws would
   drop it without a response; `dc.bsc.bacnet.org` is closed with its
   own "not supported" reason.
2. **Accepted inbound connections are identified by a connection string this
   app mints**: `<configured accept URI>|client=<unique suffix>`
   (`BACnetDataLinkSC.cpp`'s `DoesConfiguredUriMatch`). There is no
   "client connected" API - the stack learns of a peer from its first frame
   (Connect-Request). Report the source address as that string, the
   destination as the bare accept URI; every later egress to that peer
   arrives in `SendMessageForPort` with that exact string, so routing it back
   out is a plain map lookup. Max 255 bytes, no `;` in it, never reuse a
   string across sockets.
3. **The WebSocket status enum is `Connecting=1, Connected=2, Disconnected=3,
   Error=4`** (`BACnetSCConstants.h`) - the stack's own SC manual disagrees
   and is wrong (cas-bacnet-stack#3094).
4. **`SendMessageForPort` must return exactly `messageLength`** on success, 0
   if the socket is unknown/closed - not a boolean "did it work" flag
   (cas-bacnet-stack#2226). The frame is queued, and each connection's queue
   holds at most 64 frames (`kMaxTxQueueFrames`): a peer that stops reading
   is closed with 1008 and a log line, and `Send()` returns false.
5. **Callbacks dispatch by `networkPortInstance`**, not `networkType`. Inbound
   SC frames report the real SC Network Port instance (2 in the hub).
6. **Never call `BACnetStack_*` from inside a stack callback.** `Service()`
   only pumps libwebsockets and fills two queues (received frames, status
   events); only the main loop, after `Service()` returns, drains them and
   calls into the stack.
7. **The stack owns every timer** - heartbeat, Connect-Request timeouts. This
   transport only moves bytes and reports closes.
8. **Ingress ceiling is 1600 bytes** (`BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH`,
   ANSI/ASHRAE 135 Annex AB's minimum BVLC-SC relay size). A larger
   reassembled WebSocket message is dropped and logged, never handed to the
   stack.
9. **Keep one TLS context alive for the whole process.** Destroying the last
   `lws_context` created with `LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT` tears
   down OpenSSL process-wide, and the next `lws_create_context` crashes.
   `ScTransport::Configure()` creates a lifetime context that is never
   destroyed, so the listener context can be recreated safely - including
   after a failed `lws_create_context` (a busy port, a certificate that
   doesn't parse yet): the listener retries every 5 seconds and recovers once
   the cause is fixed, without a restart.

## Certificate policy

This transport performs **CA-chain validation**, at the TLS layer (OpenSSL,
via libwebsockets `ssl_ca_filepath`), and **revocation checking** when
`ScTlsFiles::crlPath` names an existing file: the
`LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS` callback loads its CRLs
into each new TLS context's store and sets `X509_V_FLAG_CRL_CHECK` (fail
closed: no CRL for the peer's issuer, or an expired one, refuses the peer; an
unparsable file stops the context). There is no UUID-in-SAN binding to a
specific BACnet/SC device identity - BACnet/SC certificates identify
*devices*, not DNS hosts. The stack has no certificate-validation callback,
so any stricter policy - identity binding, for one - belongs here, in the TLS
layer.

## Testing

`../tests/sc/` has the verification scripts (`hub_listener_test.py`,
`file_object_test.py`, `cert_procedure_test.py`, `connection_limit_test.py`,
...) and its own README explaining what each one checks and how to run it
against a live hub. Test certificates come from the demo set in `../certs/`
or from `../tools/make_test_certs.py`.
