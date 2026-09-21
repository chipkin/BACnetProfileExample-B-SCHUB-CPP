# TODO

Real, verified-absent gaps only - see the series runbook's Definition of Done:
"Every remaining `TODO.md` names a missing customer export verified absent at
the pin, dated, with a stack issue filed [where applicable]." This repository
is canonical for **F-SC**.

As of Phase 5 (dated 2026-09-21): BACnet/SC transport (both roles - listener
and connector), the 4 certificate/CSR File objects, and their binding to
Network Port 2 are all implemented and verified against real peers - see
`docs/bacnet-sc-transport-plan.md` and `CHANGELOG.md`. Nothing below blocks
this example's own NM-SCH-B claim; everything here is either a known,
documented limitation of the pinned CAS BACnet Stack build (not a bug in this
example - listed first) or a genuinely open item for the user to decide on
(listed second).

## Known, documented limitations of the pinned stack build (not bugs here)

These are real gaps, verified absent by reading `submodules/cas-bacnet-stack/source/`
at the pinned commit (`6.x` @ `abd4cee1`, 6.0.21) - not assumed. Each one is
called out in `README.md`/`sc_transport/README.md` where relevant so a reader
does not mistake the behaviour for a bug in this example.

1. **Certificate validation and CSR-generation callbacks have zero call
   sites.** `RegisterCallbackValidateBACnetSCOperationalCertificate` and
   `RegisterCallbackGenerateBACnetSCCertificateSigningRequest` are registered
   in `main.cpp` (section 2d) for documentation/completeness only - grep
   confirms neither is called anywhere in the stack's own source, only from
   the registration function itself. This device's actual (and only)
   certificate policy is the CA-chain check `sc_transport/ScTransport`'s TLS
   contexts perform. **Filed:**
   [chipkin/cas-bacnet-stack#2227](https://github.com/chipkin/cas-bacnet-stack/issues/2227).
2. **No hostname checking on the connector.** `ScTransport::Connect()` passes
   `LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK` - a deliberate choice, not an
   oversight (BACnet/SC certificates identify devices, not DNS hosts; see
   `sc_transport/README.md`), but worth naming explicitly since it is a
   security-relevant default a reader should not miss.
3. **No CRL support.** Neither this transport nor the pinned stack checks
   certificate revocation lists. A revoked device certificate is still
   accepted as long as it chains to the trusted CA.
4. **SC ingress ceiling (1497 bytes) is one octet short of Annex AB's
   1600-octet minimum BVLC size a conformant hub should be able to relay.**
   `BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH` in the pinned stack caps what
   `ReceiveMessageForPort` can hand back; a maximum-size BVLC-SC frame from a
   peer is silently dropped (logged) by `sc_transport/ScTransport`, never
   reaching the stack. Possible B-SCHUB conformance gap in the stack itself -
   **filed:** [chipkin/cas-bacnet-stack#2225](https://github.com/chipkin/cas-bacnet-stack/issues/2225).
   Do not work around this in the transport (it would require guessing at a
   larger, unsupported buffer contract); report upstream instead.
5. **Outbound SC sites pass the literal `networkPortInstance = 2`
   (`NetworkType_SC`) rather than calling `GetNetworkPortInstanceForSend()`.**
   Harmless in this example specifically because its SC Network Port instance
   *is* 2 (see the `SC_NETWORK_PORT_INSTANCE` constant's own comment in
   `main.cpp`), but it means dispatch-by-instance would silently break for any
   application whose SC port number differs. **Filed:**
   [chipkin/cas-bacnet-stack#2224](https://github.com/chipkin/cas-bacnet-stack/issues/2224).
6. **The stack's `SendMessageForPort` doc comment describes the return value
   as a boolean flag; the real SC contract requires returning exactly
   `messageLength`** (confirmed against the 4 call sites in
   `BACnetSCHubFunctionManager.cpp`/`BACnetSCHubConnector_Outgoing.cpp`).
   `ScTransportRouter` already does this correctly - this is a documentation
   defect in the stack header, not a behavioural gap. **Filed (docs-only
   fix):** [chipkin/cas-bacnet-stack#2226](https://github.com/chipkin/cas-bacnet-stack/issues/2226).
7. **The `<acceptUri>|client=<N>` accepted-peer connection-string convention
   is undocumented** anywhere except one function's behaviour
   (`BACnetDataLinkSC.cpp`'s `DoesConfiguredUriMatch`) and the stack's own
   unit tests. Load-bearing for the listener (`sc_transport/README.md` fact
   2); a future stack pin bump that changes this silently would break every
   hub host application built on it. **Filed:**
   [chipkin/cas-bacnet-stack#2223](https://github.com/chipkin/cas-bacnet-stack/issues/2223).
8. **No backpressure signal in the send contract.** `SendMessageForPort` must
   claim the full `messageLength` at enqueue time; if the socket later fails,
   the already-claimed frame is lost silently. `sc_transport/ScTransport`
   does not yet bound its per-connection transmit queue or close the socket
   on overflow - low risk at this example's demo scale (`SC_MAX_HUB_CONNECTIONS
   = 4`), but a real product built on this pattern should add a bounded queue
   (e.g. 64 frames) with close-on-overflow. **Filed as a design question, no
   stack change requested yet - this is squarely an application-layer
   concern:** [chipkin/cas-bacnet-stack#2228](https://github.com/chipkin/cas-bacnet-stack/issues/2228).
9. **The stack's own BACnet/SC manual (`docs/CAS BACnet Stack - BACnet SC
   Manual_v6.md`) has at least 5 known errors**: the WebSocket status enum
   values (says `Disconnected=1`; the header says `Disconnected=3` - see fact
   3 in `sc_transport/README.md`), stale callback signatures using
   `networkType` instead of `networkPortInstance`, a stale 6-argument
   `SetBACnetSCHubFunctionConfig` signature, the validate/CSR callbacks
   presented as live (they are not - see item 1 above), and an unguarded
   NULL-URI `memcpy` path documented in §20. This repository's own doc
   comments and `README.md` cite `CASBACnetStackDLL.h` as authoritative where
   they disagree with the manual. Filing a correction with Chipkin's stack
   documentation team is an internal follow-up, not a customer-facing stack
   issue.

## Genuinely open items for the user to decide

1. **Push / PR / merge permission.** This branch
   (`implement-bacnet-sc-transport`) is local-only, as instructed. Nothing in
   this repository has been pushed, no PR opened, no tag created.
2. ~~Filing the stack issues above with `chipkin/cas-bacnet-stack`~~ - **done**,
   2026-09-21: [#2223](https://github.com/chipkin/cas-bacnet-stack/issues/2223),
   [#2224](https://github.com/chipkin/cas-bacnet-stack/issues/2224),
   [#2225](https://github.com/chipkin/cas-bacnet-stack/issues/2225),
   [#2226](https://github.com/chipkin/cas-bacnet-stack/issues/2226),
   [#2227](https://github.com/chipkin/cas-bacnet-stack/issues/2227),
   [#2228](https://github.com/chipkin/cas-bacnet-stack/issues/2228).
3. **CI cache eviction economics.** `.github/workflows/release.yml`'s vcpkg
   binary cache (`actions/cache`, keyed on `vcpkg.json`'s hash) is evicted
   after 7 days of GitHub Actions idling it; since this workflow only runs on
   PRs/tags/dispatch (not every push), a cold ~12-20 minute Windows / ~6-10
   minute Linux vcpkg build is the *common* case for this repository, not the
   exception. Accepted during planning; flagged again here in case the user
   wants a longer-lived binary cache (e.g. a GitHub Packages NuGet source)
   once release cadence is known.
4. **A production certificate story.** This example's `certs/` are
   self-signed, single-CA, and manually regenerated
   (`scripts/generate-test-certs.cmake`) - explicitly lab-only. See
   `TUTORIAL.md`'s "Implement the BACnet/SC transport for real" section for
   what a real CA, rotation strategy, and identity policy need to look like;
   this repository intentionally does not implement any of that, since it is
   a per-deployment decision, not something a tutorial example should
   prescribe.
5. **YABE interoperability** needs
   `BACnetStack_SetBACnetSCCompatibilityFlags(0x01)` (accept a bare
   Connect-Request without a preceding Hello) - this example leaves the stack
   at its strict default and documents the flag in `TUTORIAL.md` rather than
   enabling it, since enabling it changes this device's protocol conformance
   posture and is a deployment decision, not a default this tutorial should
   make for the user.
6. **Implement a bounded transmit queue in `sc_transport/ScTransport`.**
   Item 8 above documents the gap and the upstream design question
   ([#2228](https://github.com/chipkin/cas-bacnet-stack/issues/2228)); this
   is the concrete, example-owned follow-up: bound each connection's transmit
   queue (a starting point: 64 frames, matching item 8's own estimate) and
   close the socket on overflow rather than growing the queue unbounded.
   Not implemented yet - low risk at this example's demo scale
   (`SC_MAX_HUB_CONNECTIONS = 4`), but a real, scoped task rather than only a
   documented risk.
7. **`--sc-rate-limit`'s token bucket is per-process and per-listener, not
   per-source-IP.** A single misbehaving/flooding peer and a thousand
   distinct source IPs each hammering the listener are rate-limited
   identically (the shared bucket empties either way) - this is a real,
   known weakness of the simple global-bucket design chosen for this batch
   (deliberately: a per-source-IP bucket needs a bounded eviction/aging
   policy for the tracking table itself, which is a meaningfully bigger
   design than "bound how fast this hub accepts new attempts" calls for at
   this example's scale - see `sc_transport/ScTransport.h`'s
   `SetMaxConnectionAttemptsPerSecond` comment). Practical effect: a single
   well-behaved reconnecting peer can be starved by an unrelated flood
   against the same listener. A real product exposed to an untrusted network
   should pair this with an upstream/OS-level per-IP control (a firewall
   rule, load balancer, or reverse proxy) rather than relying on this
   application-level global limiter alone.
8. **The audit trail's peer identity is the transport-level connection
   string (`"<acceptUri>|client=<N>"`), not a BACnet/SC VMAC/UUID.** This is
   the correct, honestly-available identity at the point
   `sc_transport/ScTransport` observes a connect/disconnect (see
   `README.md`'s "Rate-limiting and the audit trail" section for why a
   VMAC/UUID is not available there), but it means the audit log cannot by
   itself answer "which BACnet/SC *device* connected" across a reconnect -
   only "which accepted socket, in accept order, on this run". Correlating a
   `client=N` connection string to a BACnet/SC device identity would require
   also reading the stack's own peer table (e.g. Network Port 2's
   `SC_Hub_Function_Connection_Status` property) at the moment the stack's
   Connect-Request/Accept exchange completes for that same socket - out of
   scope for this batch (see this task's own report for why: it couples the
   audit log's timing to the stack's protocol state machine rather than the
   transport-level accept/close events this batch's audit trail is anchored
   to), but a natural next step if VMAC/UUID-level audit correlation is
   needed.
