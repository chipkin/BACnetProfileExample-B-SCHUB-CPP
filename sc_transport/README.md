# `sc_transport/` - the BACnet/SC WebSocket+TLS transport

This folder is the real WebSocket+TLS transport underneath this example's
BACnet/SC hub function (NM-SCH-B) - see the top of `../main.cpp` and
`../README.md`'s "BACnet/SC support" section for how it fits into the whole
device. This document is the **wire-level contract**: what a caller (`main.cpp`,
or your own code reusing this pattern) needs to know to drive `ScTransport`
correctly, without re-deriving it from the source.

See `ScTransport.h` and `ScTransportRouter.h`'s own header comments for the
full design rationale; this file is the summary a reader coming from
`TUTORIAL.md` needs.

## Two classes, two jobs

- **`ScTransport`** - owns the actual libwebsockets `lws_context`s (one for
  the listener, one per outbound connection) and speaks WebSocket+TLS. It
  knows nothing about BACnet or the CAS BACnet Stack's C API.
- **`ScTransportRouter`** - the glue: registers the stack's
  `ReceiveMessageForPort`/`SendMessageForPort` callbacks, dispatches between
  BACnet/IP (its own `SimpleUDP`) and BACnet/SC (`ScTransport`) by
  `networkPortInstance`, and drains `ScTransport`'s status-event queue into
  `BACnetStack_SetBACnetSCWebSocketStatus`.

## The facts that make this correct (not obvious from the stack's own docs)

These are the load-bearing details `docs/bacnet-sc-transport-plan.md`
established by reading the stack's source, not its (partly wrong - see
[cas-bacnet-stack#3094](https://github.com/chipkin/cas-bacnet-stack/issues/3094)) manual. If you are adapting this pattern to another example, or a
new stack pin, re-verify every one of these against `submodules/cas-bacnet-stack/source/`.

1. **Subprotocol is `hub.bsc.bacnet.org`** (135-2024 AB.7.1) - not
   `hub.bacnet.org`, which some other example code in this series' history
   used and which is wrong.
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
   (cas-bacnet-stack#2226).
5. **Callbacks dispatch by `networkPortInstance`**, not `networkType`. Inbound
   SC frames report the real SC Network Port instance (2 in this example).
6. **Never call `BACnetStack_*` from inside a stack callback.** `Service()`
   only pumps libwebsockets and fills two queues (received frames, status
   events); only the main loop, after `Service()` returns, drains them and
   calls into the stack. This also covers the case where lws itself invokes a
   callback synchronously from inside `Connect()` (an immediate connection
   failure can do this) - `Connect()` never touches `BACnetStack_*` either, so
   that re-entrant call is safe.
7. **The stack owns every timer** - heartbeat, reconnect, failover. This
   transport never auto-reconnects; it only dials when asked again.
8. **Ingress ceiling is 1600 bytes** (`BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH`,
   ANSI/ASHRAE 135 Annex AB's minimum BVLC-SC relay size). A larger
   reassembled WebSocket message is dropped and logged, never handed to the
   stack.
9. **Keep one TLS context alive for the whole process.** Destroying the last
   `lws_context` created with `LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT` tears
   down OpenSSL process-wide, and the next `lws_create_context` crashes
   (#13). `ScTransport::Configure()` creates a lifetime context that is
   never destroyed, so listener and client contexts can be recreated safely.

## Certificate policy

This transport performs **CA-chain validation only**, at the TLS layer
(OpenSSL, via libwebsockets `ssl_ca_filepath`/`client_ssl_ca_filepath`): no
CRL, no UUID-in-SAN binding to a specific BACnet/SC device identity, and the
connector half passes `LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK` - BACnet/SC
certificates identify *devices*, not DNS hosts, so there is nothing meaningful
to hostname-check against; the CA chain is still fully verified. See
`../TUTORIAL.md`'s "Implement the BACnet/SC transport for real" section for
what productionizing this further (a real CA, certificate rotation, an
identity-binding policy) looks like. The stack has no certificate-validation
callback (it was never called and has been removed), so any stricter policy -
revocation (#15), identity binding - belongs here, in the TLS layer.

## Testing

`../tests/sc/` has the verification scripts (`hub_listener_test.py`,
`fake_hub_server.py`, `file_object_test.py`, `cert_procedure_test.py`) and its own README explaining
what each one checks and how to run it against a live instance of this
example.
