# TODO

Real, verified-absent gaps only - see the series runbook's Definition of Done:
"Every remaining `TODO.md` names a missing customer export verified absent at
the pin, dated, with a stack issue filed [where applicable]." This repository
is canonical for **F-SC**; the gap below is a deliberate spike outcome (see
README.md "BACnet/SC support"), not a stack limitation.

## 1. BACnet/SC WebSocket/TLS transport is not implemented (spike outcome, dated 2026-09-15)

**What's missing:** an actual WebSocket(+TLS) client and listener. The CAS
BACnet Stack at the series pin (`6.x` @ `abd4cee1`, 6.0.21) implements the full
BACnet/SC *protocol* (Hello handshake, hub/node/direct-connect state machines,
BVLC framing, certificate bookkeeping) but explicitly does not implement the
transport - verbatim from `CASBACnetStackDLL.h`'s doc comment on
`BACnetStack_RegisterCallbackInitiateWebsocket`: *"The stack implements no
WebSocket or TLS itself."* This is not an absent export to file a stack issue
against - it is a documented design boundary (the stack is transport-agnostic
by design, the same way it does not open the BACnet/IP UDP socket itself
either; `common/SimpleUDP.cpp` supplies that side already).

**Exactly what a real implementation needs to add**, in `main.cpp` section 2c
(`CallbackInitiateWebsocket`, `CallbackDisconnectWebsocket`,
`CallbackSCStartListening`, `CallbackSCStopListening`):

1. A WebSocket client (for `CallbackInitiateWebsocket` - not exercised by this
   hub-only example, but the stack logs a warning if unregistered) and a
   WebSocket **listener** (for `CallbackSCStartListening` - the one this
   example actually needs for NM-SCH-B) implementing RFC 6455 framing over a
   TCP socket. This part is realistically dependency-free (a few hundred
   lines); `common/SimpleUDP.cpp` is the existing pattern for a minimal
   platform socket wrapper to build it on.
2. A TLS 1.2+ layer underneath that WebSocket transport - BACnet/SC's accept
   URIs are required to use the `wss://` scheme
   (`BACnetStack_AddBACnetSCAcceptUri`'s doc comment: *"Must use the wss
   scheme"*), so this is not optional for a conformant hub. This is the part
   that is **not** realistically dependency-free: every practical option
   vendors a crypto library (OpenSSL, mbedTLS, BoringSSL, wolfSSL, or a
   platform TLS API like Windows Schannel / macOS Secure Transport, which
   still pulls in a real state machine and certificate story). Per the task
   card, vendoring a heavyweight TLS/crypto dependency needs to be raised and
   agreed as a roadblock before doing it - it was not attempted in this spike.
3. Both directions (open on `CallbackInitiateWebsocket`, accept on
   `CallbackSCStartListening`) must be **asynchronous** - the doc comments on
   both are explicit that the stack's return-value handling differs by call
   site and that blocking stalls `BACnetStack_Tick()` for every other timer
   the stack owns, not just BACnet/SC's.
4. Every real connection/status transition must be reported back through
   `BACnetStack_SetBACnetSCWebSocketStatus(uri, status, errorCode)` - the stack
   does not infer connection state from anything else.
5. Certificate handling: `BACnetStack_SetBACnetSCCertificateFileObjects` (File
   objects for the operational certificate / CSR / issuer chain) plus the two
   certificate callbacks
   (`RegisterCallbackValidateBACnetSCOperationalCertificate`,
   `RegisterCallbackGenerateBACnetSCCertificateSigningRequest`) are configured
   nowhere in this example - a real hub needs a certificate story (even a
   simple self-signed one for a lab/demo) before an SC node will complete the
   TLS handshake at all.

**Current behaviour without the above:** the hub function is fully configured
(UUID set, accept URI added, hub function enabled) and the stack correctly
calls `CallbackSCStartListening` asking this example to start listening - so
the BACnet/SC *protocol and configuration* path is proven to run. But the
callback logs the request and returns `false`, so no real listener ever opens
and no SC node can ever connect. See README.md "BACnet/SC support" for the
full write-up (this repo is canonical for F-SC).

**Not filed as a stack issue** - see point 1 above: this is a transport
boundary by design, not a missing or broken stack export.
