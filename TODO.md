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

## Fixed since the last pin (2026-09-21, `abd4cee1` -> `53739153`)

Verified via `git fetch origin issues/runbook` + `git show 2021e29f` (the real
fix commit; `53739153` is a ledger-only follow-up, no further code changes) in
`submodules/cas-bacnet-stack` before bumping the pin. Both are real,
verified-fixed upstream (8664/8664 tests green per the commit's own report),
not just closed-without-a-fix:

- **#2224** (SC send sites passed the literal `NetworkType_SC` (2) instead of
  the real `networkPortInstance` into `SendMessageForPort`) - **CLOSED**,
  fixed in commit `2021e29f`. The 5 named call sites (plus 8 more the same
  commit found and disclosed: 7 in `BACnetBBMD.cpp`, 1 in
  `BACnetDataLink.cpp`) now call `GetNetworkPortInstanceForSend()`. See item 5
  below (moved out of "known limitations") for what this changes in this
  repository specifically.
- **#2225** (SC ingress buffer 103 bytes short of Annex AB's 1600-octet
  minimum) - **CLOSED**, fixed in the same commit `2021e29f`.
  `BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH` (`source/BACnetStackConstants.h`)
  is now gated on `STACK_OPTION_DATA_LINK_LAYER_SC` (compiled in for this
  example): 1600 bytes when SC is built in (reaching the Annex AB minimum
  exactly), `BACNET_ENCODED_FRAME_MAX_LENGTH` (1529) otherwise. This
  repository's own ingress ceiling in `sc_transport/ScTransport.cpp`/`.h`
  (`kMaxIngressBytes`) has been updated from 1497 to 1600 to match - see
  `CHANGELOG.md`.

## Known, documented limitations of the pinned stack build (not bugs here)

These are real gaps, verified absent by reading `submodules/cas-bacnet-stack/source/`
at the pinned commit (`6.x` @ `abd4cee1` at the time this list was first
written; the submodule pin is now `53739153`, see "Fixed since the last pin"
above for what changed) - not assumed. Each one is called out in
`README.md`/`sc_transport/README.md` where relevant so a reader does not
mistake the behaviour for a bug in this example.

1. **Certificate validation and CSR-generation callbacks have zero call
   sites.** `RegisterCallbackValidateBACnetSCOperationalCertificate` and
   `RegisterCallbackGenerateBACnetSCCertificateSigningRequest` are registered
   in `main.cpp` (section 2d) for documentation/completeness only - grep
   confirms neither is called anywhere in the stack's own source, only from
   the registration function itself. This device's actual (and only)
   certificate policy is the CA-chain check `sc_transport/ScTransport`'s TLS
   contexts perform. **Filed:**
   [chipkin/cas-bacnet-stack#2227](https://github.com/chipkin/cas-bacnet-stack/issues/2227) -
   closed as a **duplicate**; the real wiring is tracked upstream under their
   internal #988, still **not fixed**. The gap described above is unchanged.
2. **No hostname checking on the connector.** `ScTransport::Connect()` passes
   `LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK` - a deliberate choice, not an
   oversight (BACnet/SC certificates identify devices, not DNS hosts; see
   `sc_transport/README.md`), but worth naming explicitly since it is a
   security-relevant default a reader should not miss.
3. **No CRL support.** Neither this transport nor the pinned stack checks
   certificate revocation lists. A revoked device certificate is still
   accepted as long as it chains to the trusted CA.
4. ~~SC ingress ceiling short of Annex AB's minimum~~ - **fixed upstream, see
   "Fixed since the last pin" above** ([#2225](https://github.com/chipkin/cas-bacnet-stack/issues/2225)).
5. **Outbound SC sites used to pass the literal `networkPortInstance = 2`
   (`NetworkType_SC`) rather than calling `GetNetworkPortInstanceForSend()`
   - fixed upstream, see "Fixed since the last pin" above
   ([#2224](https://github.com/chipkin/cas-bacnet-stack/issues/2224)).** This
   was always harmless in this example specifically, because its SC Network
   Port instance *is* 2 (see the `SC_NETWORK_PORT_INSTANCE` constant's own
   comment in `main.cpp`) - so the value `ScTransportRouter::HandleSendMessage`
   dispatches on (`sc_transport/ScTransportRouter.cpp`) was already correct
   before the fix, by coincidence. After the fix it is correct because the
   stack now genuinely computes and passes the real Network Port instance,
   not because this example's port number happens to match the old buggy
   constant. No code change was needed in `ScTransportRouter.cpp` - its
   dispatch-by-instance logic was verified to still work unchanged (see
   `CHANGELOG.md` for the `networkPortInstance` debug-log verification done
   at pin-bump time).
6. **The stack's `SendMessageForPort` doc comment describes the return value
   as a boolean flag; the real SC contract requires returning exactly
   `messageLength`** (confirmed against the 4 call sites in
   `BACnetSCHubFunctionManager.cpp`/`BACnetSCHubConnector_Outgoing.cpp`).
   `ScTransportRouter` already does this correctly - this is a documentation
   defect in the stack header, not a behavioural gap. **Filed (docs-only
   fix):** [chipkin/cas-bacnet-stack#2226](https://github.com/chipkin/cas-bacnet-stack/issues/2226) -
   **partially fixed**: the SC Manual prose (`docs/CAS BACnet Stack - BACnet
   SC Manual_v6.md` §18.1) was corrected in commit `2021e29f`; the
   `CASBACnetStackDLL.h` header-comment half was explicitly routed to
   needs-human-review (the frozen public interface, out of scope for that
   resolver session) and is still **not done**.
7. **The `<acceptUri>|client=<N>` accepted-peer connection-string convention
   is undocumented** anywhere except one function's behaviour
   (`BACnetDataLinkSC.cpp`'s `DoesConfiguredUriMatch`) and the stack's own
   unit tests. Load-bearing for the listener (`sc_transport/README.md` fact
   2); a future stack pin bump that changes this silently would break every
   hub host application built on it. **Filed:**
   [chipkin/cas-bacnet-stack#2223](https://github.com/chipkin/cas-bacnet-stack/issues/2223) -
   **partially fixed**: SC Manual §18.3.1 now documents the convention
   (commit `2021e29f`); the same `CASBACnetStackDLL.h` header-comment half as
   #2226 above is still **not done** (needs-human-review).
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
10. **Network Port 2's `MAC_Address` (423) reads all-zero in this example's
    default configuration (hub-function only, no `--sc-hub-uri`) - this is
    the stack's own intended behaviour, not a bug.** Verified by reading
    `submodules/cas-bacnet-stack/source/BACnetDataLinkSC_NetworkPort.cpp`'s
    `SyncTrackedBACnetSCNetworkPort()`: `MAC_Address` is populated from
    `BACnetSCHubConnector::GetVmac()` only when a hub connector exists (i.e.
    only when `BACnetStack_SetBACnetSCHubConnectorForNetworkPort` has run at
    least once); otherwise the same function explicitly resets it to empty
    every sync cycle. There is no separate "hub function's own VMAC" setter
    anywhere in the adapter's public API. `main.cpp` previously had a
    comment here claiming the opposite ("the hub function... derives its own
    [VMAC] internally") - that was wrong and has been corrected (see the
    comment above the `--sc-hub-uri` branch in `main.cpp`'s `main()`).
    Enable `--sc-hub-uri` (which this example already computes a real VMAC
    for, from the last 6 octets of `SC_DEVICE_UUID`) to see `MAC_Address`
    populated.

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
9. **The HTTP health/metrics + certificate-upload listener (`sc_transport/HttpServer`,
   added 2026-09-21) has no TLS at all** - plain HTTP, always. `127.0.0.1`
   loopback was the ONLY bindable address in the original batch, precisely so
   the missing TLS could not matter; as of `--http-bind` (added 2026-09-22),
   that address is now a config-file/CLI-settable default, not a hard
   constraint - a deliberate, scoped follow-up the original entry here
   already anticipated ("adding one is a real, scoped follow-up, not an
   oversight"). The gap this creates is real, not just theoretical: binding
   off loopback puts `GET /health`/`GET /metrics` (no auth at all) and
   `POST /certs/<slot>`'s bearer-token check on the wire in plaintext,
   readable/interceptable by anything on that network. Mitigated, not
   eliminated, by `HttpServer::Start()` logging a `Warning` every single run
   it binds off loopback (see README.md "Health/metrics HTTP endpoint" for
   the recommended safer alternative - an SSH tunnel or a TLS-terminating
   reverse proxy in front of this listener, keeping the loopback default
   unchanged). Real TLS on this listener itself (or moving it to a Unix
   domain socket / Windows named pipe for same-host-only integrations that
   want no address to bind at all) remains unimplemented.
10. **`POST /certs/<slot>`'s authentication is a bearer token equal to
    `dcc-password`, checked with a plain string compare - not constant-time,
    not mTLS, not OAuth/a real credential/token-issuance scheme.** Reusing
    `dcc-password` was a deliberate simplification (one secret, one config
    key, matching this batch's Task 4 instructions) rather than adding a
    second credential type for a tutorial's single write endpoint; a real
    deployment should use a dedicated, rotatable upload credential (or real
    mTLS client-cert auth reusing the same PKI the BACnet/SC transport
    already has) instead of overloading the DCC password for two purposes.
    This is a strictly bigger risk now that `--http-bind` can put this
    listener on a real network (see item 9) - a plaintext bearer token is a
    materially weaker protection off loopback than on it.
11. **No rate limiting on `POST /certs/<slot>` upload *attempts* specifically**
    (as distinct from `--sc-rate-limit`, which only bounds new BACnet/SC
    WebSocket connection attempts) - an attacker who already has a valid
    `dcc-password` (or is brute-forcing a weak one) can hammer the upload
    endpoint as fast as TCP allows. Was low risk at this example's scale
    partly BECAUSE the endpoint used to be loopback-only unconditionally;
    with `--http-bind` (item 9), that mitigation is now opt-out, not
    guaranteed - a real product should add real rate limiting here regardless
    of bind address.
12. **The uploaded-certificate check is a PEM-header + size sanity check,
    not a real X.509 parse.** OpenSSL is already vendored (for the SC
    transport's TLS) and could be used for a real parse-and-sanity-check;
    this batch stuck to the simpler check on the judgement that the real
    trust decision happens at the next TLS handshake anyway (see README.md
    "Certificate upload endpoint" for the full reasoning) - revisit if this
    example ever needs to catch a malformed-but-PEM-shaped upload before it
    reaches disk, rather than only before it reaches a TLS handshake.
13. **`DeviceCommunicationControl` password-failure log lines cannot name a
    source address.** Investigated for the 2026-09-21 diagnostics pass (see
    `CHANGELOG.md`'s 1.1.8 entry): `CASBACnetStack_RegisterCallbackDeviceCommunicationControl`'s
    callback signature (`submodules/cas-bacnet-stack/adapters/cpp/
    CASBACnetStackAdapterTypes.h:191` - `deviceInstance, enableDisable,
    password, passwordLength, useTimeDuration, timeDuration, errorCode`) has
    no source-address parameter, and no other stack API exposes "which peer
    sent the message currently being processed" at the point this callback
    fires - confirmed by grepping the stack adapter headers, not assumed. A
    global "last-seen source address" set by `ReceiveMessageForPort` and
    read back here would be fragile (wrong under any request pipelining/
    reordering the stack itself does internally) for a logging nice-to-have,
    so this is left unimplemented rather than forced in.
14. **An arbitrary, unrecognised WebSocket subprotocol still drops the raw
    TCP connection with no HTTP response and no WS close frame** - the part
    of [#8](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/8)
    that the fix landed alongside this item did NOT close. `"dc.bsc.bacnet.org"`
    (a real, finite, known BACnet/SC name) is fixed - it now reaches a clean
    1002 close with an honest reason. A genuinely arbitrary name (a typo,
    garbage) cannot be, from this transport's side: verified by reading the
    pinned libwebsockets 4.5.8 source (`lib/roles/ws/server-ws.c`'s
    `lws_process_ws_upgrade`, `lib/core-net/wsi.c`'s
    `lws_vhost_name_to_protocol`) that protocol selection is a fixed-list
    exact-`strcmp` match with no wildcard, and an unmatched name is rejected
    at the raw TCP level before ANY application callback runs - not merely
    unhandled by this example's own code. Closing this fully would mean not
    relying on lws's built-in WS-role upgrade handling at all (parsing the
    HTTP upgrade request and running the WebSocket handshake by hand instead)
    - a much larger architectural change than this example's transport
    currently makes, and out of proportion to the actual practical cost (a
    confusing but harmless disconnect for a client that mistypes the
    subprotocol name).
15. ~~A mismatched private key crashes the process (segfault)~~ - **the
    reachable symptom is fixed; the underlying root cause is still unknown.**
    Originally found verifying item 3's certificate self-diagnosis: a
    mismatched key/cert pair made `lws_create_context` fail as expected, but
    the process then segfaulted - not on the first failed attempt, only on a
    **retry** (the stack calls `StartListening()`/`Connect()` again every
    Tick per its own contract). Reproduced directly (not assumed): running
    with a deliberately mismatched key, the first `lws_create_context`
    attempt fails cleanly and logs the real OpenSSL reason
    (`ssl problem getting key ... key values mismatch`); the SECOND attempt
    then crashes with `EXIT CODE 139` (SIGSEGV), inside libwebsockets' own
    subsequent context-teardown/retry path - confirmed pre-existing on the
    unmodified build via `git stash`, not introduced by the diagnostics work
    that found it.

    **Fixed at the application layer**: `LogCertificateDiagnostics()`
    (already added for item 3) now returns whether it found a *confirmed*
    mismatch (both files parsed as valid PEM, `X509_check_private_key()`
    definitively says they don't match); `StartListening()`/`Connect()` both
    now refuse to call `lws_create_context` at all in that case, logging a
    clear `"refusing to start ... certificate/private key mismatch"` error
    (via the existing `LogListenFailureOnce` de-dupe) instead of retrying
    forever. Verified: the same reproduction now runs 40+ seconds under the
    same mismatched key with zero crashes (previously crashed within ~15-20
    seconds, reliably); the valid-cert happy path is unaffected (`MATCHES`
    still logs correctly, all 3 regression suites still pass). Also fixed in
    the same pass: the per-tick retry loop was calling the full multi-line
    cert diagnostics on every single retry (~30/second once the crash no
    longer cut it short) - now rate-limited to once per 30 seconds per
    process, not per call, while still re-checking the actual match
    condition every tick (so a live fix - replacing the bad key while the
    process is still running - is still detected promptly, just not
    re-logged in full every tick).

    **What is NOT fixed, and may still be worth escalating**: the actual
    root cause - why a SECOND `lws_create_context` call after a failed first
    one crashes, specifically on this Windows/lws-4.5.8 build, and whether
    it is a real libwebsockets defect - remains uninvestigated. This
    application-layer fix makes the crash unreachable from this transport's
    own retry path (the only way `StartListening()`/`Connect()` are ever
    called repeatedly in this codebase), but does not mean the underlying
    lws/OpenSSL bug is gone - a debugger session with a real stack trace
    would be needed to root-cause it precisely enough to report upstream.
