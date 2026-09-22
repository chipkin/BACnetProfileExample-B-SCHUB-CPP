# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.13] - unreleased

### Fixed

- **`Application_Software_Version` (12) and `Firmware_Revision` (44) were
  hardcoded and stale** - found by a real device read via BACnet Explorer
  (`Application_Software_Version` reported `"1.0.0"` while the running build
  was several patch releases past that; `Firmware_Revision` was the same
  stale `"1.0.0"` constant, and was never meant to be this example's own
  version at all - it names the underlying platform). Fixed:
  `Application_Software_Version` now reads `APP_VERSION` directly (one
  source of truth, can't drift from `--version`'s own banner again).
  `Firmware_Revision` is now built at runtime from the CAS BACnet Stack's
  own `BACnetStack_GetAPIMajorVersion()`/`GetAPIMinorVersion()`/
  `GetAPIPatchVersion()`/`GetAPIBuildVersion()` (the same 4 calls
  `common/CASExampleHelper.cpp`'s `PrintVersion()` already uses for the
  startup banner), populated once right after `LoadBACnetFunctions()`
  succeeds. Verified with a real ReadProperty against the running device:
  `Application_Software_Version = "1.1.13"`, `Firmware_Revision = "6.0.21.0"`
  - both now match the actual running build instead of a 12-release-stale
  hardcoded string.

## [1.1.12] - unreleased

Routine rebuild, no functional changes - version bump only, per this
project's standing convention that any rebuild gets a patch bump first.

## [1.1.11] - unreleased

### Fixed

- **The segfault fix from 1.1.10 was too narrow - now generalized to every
  `lws_create_context` failure mode.** A subagent-driven code review of the
  branch (8 finder angles + verification) correctly flagged that the 1.1.10
  fix only refused to retry for one specific, provable cause (a confirmed
  cert/key mismatch), leaving every OTHER `lws_create_context` failure mode
  (an unparseable cert file, a port already in use) retrying unthrottled -
  the same dangerous pattern. A first attempt at the general fix (a 2-second
  retry cooldown) was tried and DISPROVED by direct reproduction: a
  deliberately corrupted cert file still crashed on the second
  `lws_create_context` attempt even with the cooldown in place, at a
  ~2-second gap rather than the original ~30-40ms - proving the crash is not
  a rate/timing issue. The actual fix is a permanent, process-lifetime latch:
  once `lws_create_context()` fails once for a role (listener or connector,
  tracked separately), it is never called again for that role this run - a
  one-shot log line explains why and that a restart is needed. Verified:
  reproduced the original crash with both an unparseable cert and a
  mismatched key/cert pair against pre-fix code (both crashed), then
  confirmed zero crashes over 40+ seconds each with the fix in place; the
  valid-cert happy path and all 3 regression suites (plus a real
  connector-role handshake against `tests/sc/fake_hub_server.py`) are
  unaffected. See `TODO.md` item 15 for the full history (including the
  wrong theories tried first) and the honestly-stated cost (a transient
  failure like a temporarily-busy port no longer self-recovers - the process
  needs a restart once `lws_create_context` has failed once).
- **Deduplicated `LWS_CALLBACK_SERVER_WRITEABLE`/`LWS_CALLBACK_CLIENT_WRITEABLE`**
  (same code review, a `simplification` finding): both cases were
  near-identical copy-pasted write-flush logic ~200 lines apart. Extracted
  into `ScTransport::FlushOneQueuedFrame()`. Verified via both halves of a
  real connector-role handshake (server write path via
  `tests/sc/hub_listener_test.py`'s V2 check, client write path via a real
  `fake_hub_server.py` exchange) and the existing regression suites - no
  behavior change, same log wording preserved on each side.
- Also removed a dead, self-contradictory placeholder comment in
  `sc_transport/ScTransport.cpp` (same review, a `simplification` finding)
  describing a mechanism that was never built.

Not addressed in this pass (lowest-severity finding from the same review,
left for a future pass rather than touching more of `main.cpp` unattended):
4 near-identical hand-rolled numeric `--flag` CLI parsers in `main.cpp`
duplicate a pattern `common/CASExampleHelper.cpp` already generalized.

## [1.1.10] - unreleased

### Fixed

- **A mismatched private key no longer crashes the process** (`TODO.md`
  item 15). Reproduced directly: with a deliberately mismatched key, the
  first `lws_create_context` attempt failed cleanly (logging the real
  OpenSSL reason), but the stack's own per-Tick retry then called
  `StartListening()`/`Connect()` again with the same known-bad pair, and
  that SECOND `lws_create_context` call segfaulted (`EXIT CODE 139`) inside
  libwebsockets' own subsequent teardown/retry path - confirmed
  pre-existing (not introduced by the previous diagnostics pass that found
  it, via `git stash` on the same test).
  `sc_transport/ScTransport.cpp`'s `LogCertificateDiagnostics()` now returns
  whether it found a *confirmed* mismatch (both files parse as valid PEM,
  `X509_check_private_key()` definitively disagrees); `StartListening()`/
  `Connect()` both now refuse to ever call `lws_create_context` in that case,
  logging a clear, de-duplicated `"refusing to start ... certificate/private
  key mismatch"` error instead. Verified: the same reproduction now runs
  40+ seconds with zero crashes (previously crashed within ~15-20 seconds,
  reliably); the valid-cert happy path and all 3 regression suites are
  unaffected.
  Also fixed in the same pass: the per-tick retry loop was re-running the
  full multi-line cert diagnostics on every retry (~30/second once the crash
  no longer cut it short) - now rate-limited to once per 30 seconds, while
  still re-evaluating the actual match condition every tick so a live fix is
  still detected promptly.
  The true root cause (why libwebsockets/OpenSSL crashes on a *second*
  `lws_create_context` call after a failed first one, on this Windows/
  lws-4.5.8 build) remains uninvestigated - this fix makes the crash
  unreachable from this transport's own retry path, not a fix to the
  underlying library behaviour. See `TODO.md` item 15 for the honest
  remaining gap.

## [1.1.9] - unreleased

### Fixed

- **`main.cpp`'s comment claiming the BACnet/SC hub-function role "derives
  its own [VMAC] internally" was wrong.** Found while reviewing Network Port
  2's properties (user report: `MAC_Address` (423) reads all-zero) - traced
  through `submodules/cas-bacnet-stack/source/BACnetDataLinkSC_NetworkPort.cpp`'s
  `SyncTrackedBACnetSCNetworkPort()`: `MAC_Address` is populated from the hub
  **connector**'s VMAC only, and is explicitly reset to empty whenever no
  hub connector is configured - there is no separate "hub function's own
  VMAC" anywhere in the adapter's public API. All-zero `MAC_Address` in this
  example's default (hub-function-only) configuration is therefore the
  stack's own intended behaviour, not a bug in this example or something
  fixable by calling another API. Comment corrected; documented as `TODO.md`
  item 10 (known, documented, not-a-bug-here) for future readers who hit the
  same question.
- **README.md's top "Versions:" banner had been stale since `v1.1.1`** - it
  was bumped once (`v1.0.0` -> `v1.1.0`) and never touched again through 8
  subsequent patch releases, still claiming `v1.1.0`/`common/` `2.6.0` while
  the actual state had moved to `v1.1.8`/`2.7.0`. Corrected to the current
  versions, with a note pointing at `CHANGELOG.md` as the authoritative
  per-release record if this drifts again.

Also documented (not fixed, out of scope for a doc-only patch): `TODO.md`
item 15 - a mismatched private key segfaults the process on this
Windows/lws-4.5.8 build instead of returning a clean error, found and
confirmed pre-existing while verifying the previous batch's certificate
self-diagnosis work.

## [1.1.8] - unreleased

### Added

Diagnostic/observability pass answering "what other information can we add
to the log to help diagnose issues with the BACnet/SC connect, or the
certificates, or other errors" - 5 real, verified gaps closed, all in
`sc_transport/ScTransport.cpp`/`.h` and `main.cpp`:

- **A rejected mTLS handshake is now visible.** Previously a client whose
  certificate did not chain to `certs/ca.crt` failed inside OpenSSL, under
  `LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT`, before
  `LWS_CALLBACK_ESTABLISHED` or any other application callback fired - zero
  application-level trace. `sc_transport/ScTransport.cpp` now handles
  `LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION` (verified against
  the pinned lws 4.5.8 header: this reason fires during OpenSSL's own
  client-cert chain verification, with `user`/`in`/`len` giving the
  `X509_STORE_CTX*`/`SSL*`/`preverify_ok`) and logs a `Warning` naming the
  OpenSSL verify error (`X509_verify_cert_error_string`) and the presented
  certificate's subject/issuer CN, without changing the accept/reject
  decision itself (the mandatory chain check is unaffected either way - this
  callback mirrors `preverify_ok` back to lws unchanged). Verified against a
  self-signed rogue certificate not signed by `certs/ca.crt` - see this
  task's own report for the exact log line.
- **Source IP:port added to connect/disconnect/rate-limit-rejection log
  lines.** `PeerAddressPort(lws*)` (new, `ScTransport.cpp`) combines
  `lws_get_peer_simple()` (IP only) with a raw `getpeername()` on the
  underlying socket (`lws_get_socket_fd()`) for the port lws has no
  higher-level accessor for. Added to the listener's accept log + `SC audit:
  ... connected` line, the disconnect audit line (reusing the address
  captured once at `ESTABLISHED`, since the socket may already be gone by
  `CLOSED`), the `--sc-rate-limit` rejection line (verified callable that
  early, against the raw `LWS_CALLBACK_FILTER_NETWORK_CONNECTION` accept
  socket), and - lower priority, since the connector already knows what URI
  it dialed - the connector's own established/error/closed lines.
- **Startup certificate self-diagnosis.** New `LogCertificateDiagnostics()`
  (`ScTransport.cpp`), called once per `StartListening()`/`Connect()` (not
  per-connection, and independent of the missing-file check below - it runs
  even when the files ARE readable): parses `certPath`/`caCertPath` with
  OpenSSL's X.509 API and logs subject/issuer CN, notBefore/notAfter as a
  human day-count (`Warning` under 30 days or already expired - never a raw
  `ASN1_TIME`), whether `keyPath`'s private key actually matches `certPath`
  (`X509_check_private_key` - the single most common real misconfiguration,
  previously indistinguishable from every other "cert files malformed?"
  failure), and SAN entries (`Info` only - this transport's connector still
  deliberately skips hostname checking, unchanged).
- **Per-file missing/unreadable detail.** `StartListening()`'s and
  `Connect()`'s cert-file checks now name specifically which of
  cert/key/ca actually failed `FileReadable()` (new
  `DescribeMissingTlsFiles()` helper), instead of bundling all three into
  one message regardless of which one is the actual problem.
- **libwebsockets' own logging now goes through `CASExampleHelper::Log`.**
  `main.cpp` calls `lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE,
  &LwsLogCallback)` once at startup, before any `lws_context` is created.
  `LwsLogCallback` strips lws's own trailing newline and maps `LLL_ERR`/
  `LLL_WARN`/everything-else to this app's Error/Warning/Info levels -
  lws's internal debug lines (e.g. the `lws_tls_server_accept: client cert
  CN '...'` line that used to be the ONLY trace of a rejected handshake) now
  carry this app's own UTC timestamp and level tag instead of printing
  however lws's build default happened to configure them.

Investigated (per this task's own instructions) whether
`DeviceCommunicationControl` password-failure log lines could also name a
source address - **confirmed NOT cleanly implementable**:
`CASBACnetStack_RegisterCallbackDeviceCommunicationControl`'s callback
signature (`submodules/cas-bacnet-stack/adapters/cpp/
CASBACnetStackAdapterTypes.h:191`) carries no source-address parameter, and
no other stack API exposes "which peer sent the message currently being
processed" at that callback's firing point (grepped the stack adapter
headers for anything resembling a "current source"/"last message" accessor -
none exists). See `TODO.md`'s "Genuinely open items" for the honest note
added there instead of a fragile global-variable workaround.

## [1.1.7] - unreleased

### Added

- **`--http-bind <addr>` setting** (config-file key `http-bind`, same
  CLI-over-config precedence as everything else): the interface
  `sc_transport/HttpServer` binds to, previously hardcoded to `127.0.0.1`
  with no way to change it. Defaults to `127.0.0.1` unchanged. Binding to
  `0.0.0.0` or a LAN address now works (verified: a real HTTP client on the
  loopback-external side of a non-loopback bind successfully reached
  `GET /health`), but this listener still has **no TLS**, and `GET /health`/
  `GET /metrics` still have **no authentication** - `HttpServer::Start()` now
  logs a `Warning`-level line every single run it binds to anything other
  than `127.0.0.1`/`localhost`, so this cannot go unnoticed. See README.md
  "Health/metrics HTTP endpoint" for the recommended safer alternative (an
  SSH tunnel or TLS-terminating reverse proxy) if off-host access is needed
  without accepting that tradeoff. `TODO.md` items 9-11 updated to reflect
  that the loopback-only mitigation they described is now opt-out, not
  guaranteed.

## [1.1.6] - unreleased

### Fixed

- **Unrecognised WebSocket subprotocol no longer drops the raw TCP
  connection for the one case this example can actually fix**
  ([#8](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/8)).
  `sc_transport/ScTransport.cpp`'s listener now registers
  `"dc.bsc.bacnet.org"` (135-2020 AB.7.1's direct-connect subprotocol) as its
  own protocol entry alongside `"hub.bsc.bacnet.org"`, so a client that
  requests it reaches the existing `LWS_CALLBACK_ESTABLISHED` check and gets
  a clean WS close (1002) with an honest reason - "direct-connect
  (dc.bsc.bacnet.org) not supported by this hub" - instead of a bare TCP
  reset indistinguishable from a firewall drop or a crashed hub. Verified
  with the same 4-request probe the issue used: `101` + echoed
  `Sec-WebSocket-Protocol: dc.bsc.bacnet.org` + the close reason above, now
  observed on the wire.
  An initial attempt at this fix tried registering an empty-name (`""`)
  catch-all protocol entry, hoping libwebsockets would treat it as "bind any
  subprotocol lws doesn't otherwise recognise here." Rebuilding and
  re-running the same probe disproved that - reading the pinned lws 4.5.8
  source (`lib/core-net/wsi.c`'s `lws_vhost_name_to_protocol`) confirmed
  protocol selection is a straight `strcmp` loop with no wildcard, so an
  empty registered name only matches a client that sends a literally empty
  subprotocol token. A genuinely **arbitrary** unrecognised subprotocol name
  (a typo, garbage) is still dropped at the raw TCP level - `lws_process_ws_
  upgrade` rejects it before any application callback runs at all, and there
  is no fix for that from this transport's side without bypassing lws's own
  WS-role upgrade handling entirely. See `TODO.md` for this documented,
  verified-real, deliberately-not-fixed-here limitation.

## [1.1.5] - unreleased

### Added

- **Task 3: read-only health/metrics HTTP endpoint** - `GET
  http://127.0.0.1:<http-port>/health` and `GET .../metrics` (identical),
  no authentication, JSON body (uptime, BACnet/SC hub connection count vs
  `--sc-max-hub-connections`, cumulative connect/disconnect/rate-limit-rejection
  counters, RX/TX message/byte counters). New `sc_transport/HttpServer.h`/`.cpp`,
  built on the already-vendored `libwebsockets` HTTP-server callbacks
  (`LWS_CALLBACK_HTTP`/`LWS_CALLBACK_HTTP_WRITEABLE`/etc.) - no new vcpkg
  dependency. Bound to `127.0.0.1` only, on a new `--http-port <n>` /
  config-file `http-port` setting (default `8080`). See README.md
  "Health/metrics HTTP endpoint".
- **Task 2: `m` keypress prints the same health/metrics snapshot as plain
  text** to stdout, using the identical data source (`ScTransport::GetMetrics()`,
  `main.cpp`'s `BuildHealthJson()`/`PrintHealthSnapshot()`) so the keypress and
  the HTTP endpoint can never drift apart. `ScTransport` gained cumulative
  counters (`ScTransportMetrics`: total connects/disconnects, rate-limit
  rejections, RX/TX messages and bytes) reusing the existing audit-trail
  (`LWS_CALLBACK_ESTABLISHED`/`CLOSED`) and rate-limiter (`AllowNewConnectionAttempt`)
  call sites rather than a second bookkeeping scheme. `common/` bumped to
  2.7.0 for the new `KeyCommand::Metrics` ('m'/'M') enum value - see
  `common/CHANGELOG.md`.
- **Task 4: `POST /certs/<slot>` certificate/CSR upload endpoint**
  (`<slot>`: `operational`, `csr`, `issuer1`, `issuer2`) writes an uploaded
  file into `--sc-cert-dir`, replacing the corresponding file the 4 read-only
  File objects already serve. Requires `Authorization: Bearer <dcc-password>`;
  rejected `401` with no/wrong token; **disabled entirely** (`503`, every
  attempt logged) if `dcc-password` is unset - an empty password never means
  "no auth required". PEM-header + size sanity check (not full X.509
  validation - a deliberate, documented tradeoff, see README.md). Atomic
  write (temp file + rename) so a peer reading the live file via
  `AtomicReadFile` mid-upload is never handed a partial write. Every attempt
  (success and every rejection reason) logged via `CASExampleHelper::Log`.
  Shares the Task 3 HTTP listener/port, but the auth requirement is a hard
  branch on HTTP method in `HttpServer::HandleHttp` so it cannot leak between
  the two routes in either direction. See README.md "Certificate upload
  endpoint" for the full safety writeup, including what is honestly NOT
  hardened (no TLS on this listener, no per-upload rate limiting, bearer
  token rather than mTLS/OAuth) and `TODO.md`'s "Genuinely open items" for
  the same, tracked.

### Changed

- **Task 1: `--dcc-password <string>` REMOVED from the command line.** The
  DeviceCommunicationControl password is now settable **only** via the
  `--config` file's `dcc-password` key - a CLI argument is visible in process
  listings/shell history on every platform, a real exposure for a secret.
  `--dcc-password` no longer appears in `--help` output
  (`CASExampleHelper::HandleHelpAndVersionArgs` gained an optional, default-`true`
  `showDccPasswordCliOption` parameter in `common/` 2.7.0 - this repo passes
  `false`; every other example's `--help` is unaffected). An unrecognised
  `--dcc-password <value>` on this repo's command line is now silently
  ignored, matching this codebase's existing convention for any unknown flag
  (no CLI argument parser here treats an unrecognised flag as a hard error).
  `common/CASExampleHelper::ParseDccPasswordArg()` itself was **kept, not
  removed**, from `common/` - see `common/CHANGELOG.md`'s 2.7.0 entry for the
  full reasoning (it was published in `common/` 2.6.0 the same day this
  decision was made, with no evidence any sibling example repo has adopted it
  yet, so removing a function the moment after publishing it was judged more
  invasive than simply not calling it from this one repo).
- **New: config-file secret-permission warning.** At `--config` load time, if
  the file sets a non-empty `dcc-password`, `config.cpp` checks the file's
  own permissions and logs a `Warning` (via `CASExampleHelper::Log`) if it
  looks readable by more than its owner/Administrators - exact on
  Linux/macOS (POSIX mode bits), a best-effort DACL heuristic on Windows
  (`GetNamedSecurityInfoA`/`GetAce`, flags `Everyone`/`Authenticated
  Users`/`BUILTIN\Users` ALLOW entries). A warning, not enforcement - the
  device still starts. See README.md "Secrets handling".
- `example.conf` documents `http-port` and reinforces that `dcc-password` is
  config-file-only.
- `APP_VERSION` `1.1.4` -> `1.1.5`.

## [1.1.4] - unreleased

### Changed

- **Submodule pin bump**: `submodules/cas-bacnet-stack` moved from `abd4cee1`
  to `53739153` on `issues/runbook` (fetched fresh and verified via
  `git show 2021e29f`, the real fix commit; `53739153` is a ledger-only
  follow-up with no further code changes). Picks up real, verified-fixed
  upstream behaviour for two issues this example filed:
  - **[#2224](https://github.com/chipkin/cas-bacnet-stack/issues/2224)** - SC
    send sites (and, disclosed as scope expansion in the same commit, the
    equivalent BACnet/IP BBMD/generic-data-link sites) now pass the real
    `GetNetworkPortInstanceForSend()` value into `SendMessageForPort` instead
    of the literal `NetworkType_SC` (2) byte that was there before.
  - **[#2225](https://github.com/chipkin/cas-bacnet-stack/issues/2225)** -
    `BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH` is now 1600 bytes when
    `STACK_OPTION_DATA_LINK_LAYER_SC` is compiled in (was 1497, 103 bytes
    short of Annex AB's 1600-octet minimum BVLC-SC relay size).
  - `sc_transport/ScTransport.cpp`/`.h`'s own `kMaxIngressBytes` ingress
    ceiling constant and its surrounding comments were updated from 1497 to
    1600 bytes to match the new stack constant - this transport still
    enforces a finite ceiling, just the corrected one.
  - `sc_transport/README.md` fact 8 and `TODO.md` updated to match (moved
    #2224/#2225 into a new "Fixed since the last pin" section; #2223/#2226
    marked partially fixed - SC Manual prose done in the same upstream
    commit, the `CASBACnetStackDLL.h` header-comment half still
    needs-human-review upstream; #2227 marked closed as a duplicate, real fix
    still tracked under the stack's internal #988, not yet done; #2228
    unchanged - still open, no code expected).
  - `ScTransportRouter`'s dispatch-by-`networkPortInstance` logic
    (`sc_transport/ScTransportRouter.cpp`) required **no code change**: this
    example's `SC_NETWORK_PORT_INSTANCE` is already 2, so the value it
    received was already correct before the fix (by coincidence - matching
    the old buggy constant) and remains correct after it (now because the
    stack genuinely computes the real instance). Verified directly against
    the post-bump build, no temporary debug code needed:
    `ScTransportRouter::HandleSendMessage` already logs the
    `networkPortInstance` it receives on every SC send
    (`TX N bytes to SC peer "..." (Network Port <networkPortInstance>)`);
    running `tests/sc/hub_listener_test.py`'s V2 case against the rebuilt
    `BACnetExampleBSCHUB.exe` produced `TX 34 bytes to SC peer
    "wss://0.0.0.0:47819/|client=3" (Network Port 2)` - confirming the stack
    now passes the real Network Port instance (2), not merely "some value".
  - No `docs/objects.json` changes; `docs/PICS.md` regeneration was skipped
    accordingly (dependency/bugfix pin bump only, no object-model change).

## [1.1.3] - unreleased

### Added

- **BACnet/SC hub-function connect/disconnect audit trail** (Task 1 of this
  batch): `sc_transport/ScTransport.cpp` now logs, via
  `CASExampleHelper::Log` at `Info` level, every accepted listener-side peer
  connecting/disconnecting: `SC audit: peer "<acceptUri>|client=<N>"
  connected` / `... disconnected (closeCode=<n>)`. The identifier is the
  accepted-peer connection string - the same identity this transport already
  uses as the peer's BACnet/SC source address - since a BACnet/SC VMAC/UUID
  is not available at the transport layer (it is only established once the
  stack completes its own Connect-Request/Accept exchange, which is ordinary
  RX data this layer relays but does not parse). No new file/rotation system
  - real-time structured log output, per the task's own scope. **Verified**
  with two real, distinct mutually-TLS WebSocket peers connecting and one
  cleanly disconnecting - see this task's own report for the captured log
  output (both `connected` lines with distinct `client=N` ids, one clean
  `disconnected (closeCode=1000)` line, plausible UTC timestamps from
  `CASExampleLog`'s own prefix).
- **`--sc-rate-limit <n>` connection-attempt rate limiting** (Task 2 of this
  batch): bounds how fast the hub-function listener accepts NEW inbound
  connection *attempts* - a token bucket (burst = `n`, refill `n`/sec) in
  `sc_transport/ScTransport`, gated in `HandleServerCallback`'s
  `LWS_CALLBACK_FILTER_NETWORK_CONNECTION` case - the earliest hook lws
  offers, firing at raw-socket accept() time, before the TLS handshake
  starts. Rejects (closes immediately, no TLS/WS resources spent) and logs
  at `Warning` level: `SC rate limit: rejecting new connection attempt on
  <uri> - more than <n> attempt(s)/sec (rejected before TLS handshake; see
  --sc-rate-limit)`. Distinct from `--sc-max-hub-connections`, which bounds
  *concurrent* connections at the BACnet/SC protocol level (after a full TLS
  handshake), not the rate of new attempts. Default `10`/sec (generous - a
  real reconnect storm from this example's own demo peers is nowhere near
  this rate); `0` disables it. Wired into the config-file system the same
  way as `--sc-max-hub-connections` (`config.h`/`config.cpp`'s `sc-rate-limit`
  key, `example.conf`, CLI > config file > built-in default) and `--help`.
  **Verified** with a burst of 20 near-simultaneous connection attempts
  against `--sc-rate-limit 3`: the first burst (token-bucket capacity)
  succeeded, the remainder were rejected with the warning log line above, and
  a later attempt (after enough time had passed to refill one token)
  succeeded again - see this task's own report for the captured log output.
  Documented in `README.md` ("Rate-limiting and the audit trail").

## [1.1.2] - unreleased

### Added

- **DS-RPM-B (ReadPropertyMultiple) support.** `main.cpp` now enables
  `SERVICE_READ_PROPERTY_MULTIPLE` alongside `SERVICE_READ_PROPERTY` -
  confirmed by reading `submodules/cas-bacnet-stack/source/BACnetReadPropertyMultipleProcessor.cpp`
  that RPM resolves every requested property through the same
  `BACnetBusinessLogic::GetProperty` path single-property ReadProperty uses,
  so no additional Get callback is needed. Verified with a real
  `bacpypes3` client issuing a single ReadPropertyMultiple request for the
  Device object's `Object_Name` + `Vendor_Identifier` in one PDU - see this
  task's own report / `tests/sc/` for the ad hoc script. `docs/PICS.md` and
  `README.md`'s BIBB tables updated to claim DS-RPM-B; `docs/PICS.md`'s
  objects/properties block regenerated with `tools/gen-objects-properties.py`.
- **`--config <path>` configuration file** (Task 2): a dependency-free,
  INI-like `key = value` file (`config.h`/`config.cpp`, example-local, not
  `common/`) providing DEFAULTS for `device-id`, `port`, `sc-port`,
  `sc-cert-dir`, `sc-hub-uri`, `sc-failover-uri`, `dcc-password`, and
  `sc-max-hub-connections`. Precedence is **CLI args > config file > built-in
  defaults** - each existing `Parse*Arg()` call is handed the config-file
  value (if present) as its own default, so a CLI flag still wins with no
  separate override pass. `example.conf` ships as a checked-in template (not
  gitignored - only `certs/` and build output are). Documented in
  `README.md` ("Configuration file") and `TUTORIAL.md`.
- **`--sc-max-hub-connections <n>` runtime setting** (Task 3): the BACnet/SC
  hub function's max simultaneous inbound peer connections, previously the
  hardcoded `SC_MAX_HUB_CONNECTIONS = 4` constant. Now `g_scMaxHubConnections`
  (default `SC_MAX_HUB_CONNECTIONS_DEFAULT = 4`), settable via
  `--sc-max-hub-connections` or the config file's `sc-max-hub-connections`
  key (CLI > config > default, same precedence as Task 2), threaded into
  `BACnetStack_SetBACnetSCHubFunctionConfig`. **Enforcement verified**: the
  limit is enforced by the CAS BACnet Stack itself, at the BACnet/SC protocol
  layer (`BACnetSCHubFunctionManager.cpp` rejects a Connect-Request past the
  configured max with `HubFunctionPeerUpsertResult_TableFull`) - see this
  task's own report for the exact verification method and its result
  (including whether it was possible to observe from outside the process).

## [1.1.1] - unreleased

### Added

- **Shared `common/` structured logging facility** (`CASExampleLog.h/.cpp`,
  `common/` 2.6.0): `CASExampleHelper::Log(level, fmt, ...)` with
  Debug/Info/Warning/Error levels and a runtime-configurable minimum
  (`SetLogLevel`/`GetLogLevel`). This repo is the first adopter: 3
  demonstrative call sites in `main.cpp` (the DeviceCommunicationControl
  password-failure rejection, the "could not read a local IPv4 address"
  fallback, and the BACnet/SC hub accept-URI failure) now go through it.
- **`DCC_PASSWORD` is now a setting**, not a hardcoded constant:
  `CASExampleHelper::ParseDccPasswordArg()` (`common/` 2.6.0) parses
  `--dcc-password <string>` following the existing `ParsePortArg` pattern;
  `main.cpp`'s `g_dccPassword` replaces the old
  `static const char* DCC_PASSWORD = "";`. Default remains `""` (no password
  required) for anyone who does not pass the flag.

## [1.1.0] - unreleased

A new capability over v1.0.0: **the BACnet/SC transport is now real, both
roles** (hub-function listener and hub connector), not the documented stub
v1.0.0 shipped with. See "Roadblock cleared" below for why v1.0.0 shipped
without it, and `docs/bacnet-sc-transport-plan.md` for the full design and
phase-by-phase verification record this entry summarizes.

### Added

- **BACnet/SC hub-function (listener) transport is now real**, not a stub:
  `sc_transport/ScTransport` (libwebsockets + OpenSSL, mutual TLS 1.3,
  subprotocol `hub.bsc.bacnet.org`) and `sc_transport/ScTransportRouter` (the
  stack&lt;-&gt;transport glue, dispatching by Network Port instance).
  `main.cpp`'s four transport callbacks (section 2c) are thin forwards to
  `ScTransport`; `CallbackSCStartListening`/`CallbackSCStopListening` are
  fully real. `scripts/generate-test-certs.cmake` (`cmake --build build
  --target test-certs`) generates lab-only self-signed certs under `certs/`
  (gitignored). New CLI options `--sc-port` (default 47819) and
  `--sc-cert-dir` (default `./certs`).
- **BACnet/SC hub-connector (initiate) transport is now real**, not a stub:
  `ScTransport::Connect()`/`Disconnect()` - one client `lws_context` per
  connection, subprotocol `hub.bsc.bacnet.org`, mutual TLS 1.3, the same
  binary-frame/reassembly/1497-byte-ingress rules the listener half enforces
  (shared via `HandleIncomingFragment`). No auto-reconnect: the stack owns
  every retry timer - this class only dials when asked.
  `CallbackInitiateWebsocket`/`CallbackDisconnectWebsocket` in `main.cpp` are
  real forwards. New CLI options `--sc-hub-uri <wss://...>` (turns the
  connector role on; off by default) and `--sc-failover-uri` (optional),
  wired to `BACnetStack_SetBACnetSCHubConnectorForNetworkPort`.
- **4 read-only File objects**: File 1 "Ivory" (operational certificate,
  `certs/hub.crt`), File 2 "Ivory 2" (certificate signing request,
  `certs/hub.csr`), and File 3/4 "Ivory 3"/"Ivory 4" (the 2 required
  issuer-certificate slots, both `certs/ca.crt` in this lab setup), all
  stream-access via `BACnetStack_AddFileObject` and bound to Network Port 2
  with `BACnetStack_SetBACnetSCCertificateFileObjects`. `main.cpp`'s
  `CallbackReadFile` (section 2d) serves the real bytes of each file straight
  off disk under `--sc-cert-dir` - never `certs/hub.key`, which has no File
  object at all. `RegisterCallbackValidateBACnetSCOperationalCertificate`/
  `RegisterCallbackGenerateBACnetSCCertificateSigningRequest` are also
  registered, for documentation/completeness only - both have zero call sites
  in this stack build (see `TODO.md`), so registering them provides no real
  certificate-validation security. AtomicReadFile is now enabled - its own
  confirmed service, not implied by adding a File object. No WriteFile: this
  device stays read-only.
- **`common/` synced to 2.6.0** (`CASExampleHelper.h`'s `COMMON_VERSION`; see
  `common/CHANGELOG.md`): a new structured logging facility
  (`CASExampleLog.h`/`.cpp`, `CASExampleHelper::Log(level, fmt, ...)` with
  `Debug`/`Info`/`Warning`/`Error` levels and a runtime-configurable minimum)
  and `CASExampleHelper::ParseDccPasswordArg()` (`--dcc-password <string>`).
  This repo is the first adopter of both: `main.cpp` converts 3 log call
  sites (the DeviceCommunicationControl password-failure rejection, the
  "could not read a local IPv4 address" fallback, and the BACnet/SC hub
  accept-URI failure) to `CASExampleHelper::Log`, and its DCC password is now
  parsed from `--dcc-password` (`g_dccPassword`, default `""`) instead of the
  old hardcoded `static const char* DCC_PASSWORD = "";`.
- `sc_transport/README.md` - the wire-level transport contract (subprotocol,
  connection-string convention, status enum, send/receive semantics,
  certificate policy) referenced from `main.cpp`'s header and `TUTORIAL.md`.
- `THIRD-PARTY-NOTICES.md` - licence notices for the two dependencies the
  BACnet/SC transport links: libwebsockets (MIT) and OpenSSL 3 (Apache-2.0),
  both fetched via vcpkg (`vcpkg.json`), never vendored.
- `.github/workflows/release.yml` now builds with vcpkg (`actions/cache`
  keyed on `vcpkg.json`'s hash, `VCPKG_ROOT`/`VCPKG_BINARY_SOURCES` wired to a
  workspace-local binary cache, and the builtin-baseline fetch workaround for
  a runner whose bundled vcpkg clone predates the manifest's pinned baseline
  - adapted from `../plugfest-example/.github/workflows/build.yml`), and,
  after the existing smoke test, generates certs, starts the executable, and
  runs the `tests/sc/` verification scripts (`hub_listener_test.py`,
  `file_object_test.py`) via a new `actions/setup-python` step. The package
  step now also ships `scripts/` and `THIRD-PARTY-NOTICES.md`.

### Changed

- Restructured documentation to match the series' README/TUTORIAL/PICS split
  (see `BACnetProfileExample-B-SS-CPP`): `README.md` is cut down to this
  example only (device tree, BIBBs/services/object types, licensing, build,
  run, verify, footprint, series table, references); the "Before you ship"
  table moved into per-field comments in `main.cpp`'s
  `CHANGE ALL OF THIS BEFORE YOU SHIP` block; "Extending the example",
  "Troubleshooting" and the `BACnetStack_Tick()` contract moved into a new
  `TUTORIAL.md`; the "Objects and properties" block moved into a new
  `docs/PICS.md` (ANSI/ASHRAE 135 Annex A shape), regenerated with zero ⚠
  rows; `docs/objects.json`'s Device entry now splits `stack` (device-wide
  facts the stack computes) from `accepted` (stack defaults the app
  deliberately leaves alone), matching the series convention.
- **Build switched from STATIC to the adapter's default SOURCE mode**: the
  documented build is now the same two commands as every other example in the
  series (`cmake -B build -S .` / `cmake --build build --config Release`), now
  with `VCPKG_ROOT` also required (see README.md "Prerequisites") for the new
  `libwebsockets`/`openssl` dependencies - no `tools/build-stack-static.sh`
  pre-step and no `-DCAS_BACNET_STACK_LINK=...` flag. `.github/workflows/release.yml`
  drops the static-library cache/build steps and the matrix `lib:` entries,
  configures without a link-mode flag, asserts `CAS_BACNET_STACK_LINK=SOURCE`,
  records `"link_mode": "SOURCE"` in `metrics-*.json`, and packages
  `TUTORIAL.md` / `docs/PICS.md` into the release artifact. The v1.0.0
  footprint numbers in README.md were measured from the old STATIC build; a
  future release refreshes them under SOURCE (+vcpkg dependencies).
- `main.cpp`'s file-header comment (BACnet/SC transport section) rewritten in
  present tense: the "transport is a stub" spike finding is gone (see
  "Roadblock cleared" below - it is now history, not current state), replaced
  by a description of the real transport, both roles, and their verification
  against real peers. `APP_VERSION` bumped `1.0.0` -> `1.1.0` (new capability).
- `AGENTS.md` - "stubs by design" framing removed (both transport callbacks
  are real now); layout section documents `sc_transport/`, `scripts/`,
  `tests/sc/`, `THIRD-PARTY-NOTICES.md`; new licence and vcpkg-prerequisite
  build notes.
- `TUTORIAL.md` - "Implement the BACnet/SC transport for real" is reframed
  from "what a stub needs to become real" to "how the real transport works
  and how to productionize it further" (a real CA, certificate rotation,
  hostname/identity policy notes, pointers to `sc_transport/README.md`).
- `TODO.md` item 1 (the old "transport is a stub" item) replaced with the
  genuine remaining gaps: a set of known, documented stack-build limitations
  (certificate-validation callbacks not wired up, no hostname check on the
  connector by design, no CRL support, the 1497-byte SC ingress ceiling vs.
  Annex AB's 1600-octet BVLC minimum, and others - see `TODO.md` for the full,
  distinguished list) plus genuinely open items for the user (push/PR
  permission, whether to file the stack issues upstream, CI cache-eviction
  economics, a production certificate story).
- **Network Port and File object names changed from colour names to purpose
  names**, a deliberate departure from this series' usual colour-naming
  convention for these 6 objects specifically: Network Port 1 "Vermilion" ->
  "BACnet IP", Network Port 2 "Vermilion 2" -> "BACnet SC", File 1 "Ivory" ->
  "Operational Certificate", File 2 "Ivory 2" -> "CSR", File 3 "Ivory 3" ->
  "Issuer Certificate Slot 1", File 4 "Ivory 4" -> "Issuer Certificate Slot
  2". The Device and the three sensor inputs (Rainbow/Bronze/Emerald/Hot
  Pink) keep their colour names. Re-verified live: `tests/sc/file_object_test.py`
  still passes 3/3 (`AtomicReadFile(File 1, "Operational Certificate")`
  byte-for-byte, `Issuer_Certificate_Files` still 2 entries, the key still
  unreachable).
- **README.md, TUTORIAL.md and tests/sc/README.md rewritten to drop
  process-history framing** ("used to be a stub," "Phase N," comparisons to
  the pre-transport state) in favour of describing only the current,
  present-tense behaviour. `docs/bacnet-sc-transport-plan.md` and
  `docs/bacnet-sc-planning-prompt.md` remain in the repository as the design
  record, but README.md no longer cites them as the primary source for what
  the transport does - it cites `sc_transport/README.md` and `TODO.md`
  instead. Two stale claims left over from before the transport went from
  stub to real were also found and fixed in `docs/objects.json`/`docs/PICS.md`
  (Network Port 2's note, the NM-SCH-B BIBB row, and the Annex 7/9 datalink
  sections still said "the WebSocket/TLS transport is a documented stub... no
  BACnet/SC node can connect in this build") - these were checked, not
  assumed, and corrected to match the real, verified current behaviour.

### Verified

- **V1-V2 (listener, `tests/sc/hub_listener_test.py`)**: TLS 1.3 negotiates
  and the server echoes the `hub.bsc.bacnet.org` subprotocol; the required
  negative cases (no client cert, TLS 1.2, wrong subprotocol, a text frame)
  are all refused/rejected/closed(1003); a hand-built BVLC-SC Connect-Request
  gets a real Connect-Accept back.
- **V3 (a real peer)**: `BACnetSCCli.exe`, `Role=node`, completed
  Who-Is/I-Am/ReadProperty discovery of this device (`Object_Name` =
  `"Rainbow"`) over BACnet/SC.
- **V4 (connector, `tests/sc/fake_hub_server.py`)**: a hand-built mutual-TLS
  fake hub answers the example's Connect-Request with a Connect-Accept; the
  example's own state-change log reaches `Connected`; killing the fake hub
  produces a `Disconnected` log line, with the STACK - not `ScTransport` -
  confirmed to be the one re-dialing afterwards (`ScTransport::Connect()`
  never calls itself).
- **V5 (connector vs. a real hub)**: `BACnetSCCli.exe`, `Role=hub`,
  `AllowLegacyConnectRequestsWithoutHello=false` - the example's own
  hub-connector state machine reaches `HubConnectorState_ConnectedPrimary`,
  independently confirmed by the real hub's own log decoding the example's
  Connect-Request.
- **V6 (File objects, `tests/sc/file_object_test.py`)**: over BACnet/IP with a
  hand-built `bacpypes3` client: `AtomicReadFile(File 1)` returns the bytes of
  `certs/hub.crt` byte-for-byte; Network Port 2's `Issuer_Certificate_Files`
  has exactly 2 entries; every File object (1-4) was enumerated and read, and
  none served `certs/hub.key`.
- **V7 (regression + gates, this phase)**: BACnet/IP Who-Is/I-Am confirmed to
  keep answering normally (5/5 rounds) while a mutual-TLS BACnet/SC peer
  connection is held open concurrently, over the SAME running instance -
  proving `ScTransportRouter`'s IP-first/SC-first alternating poll does not
  starve either datalink; `--help`/`--version` (prints `v1.1.0`); running
  without `certs/` prints the documented clean message and BACnet/IP keeps
  working; full clean rebuild (`cmake --build build --config Release`, zero
  warnings from `main.cpp`/`sc_transport/`/`common/`) and `--version` confirms
  `v1.1.0`; `python tools/gen-objects-properties.py BACnetProfileExample-B-SCHUB-CPP
  --check` passes with zero ⚠ rows (from the series root). Windows build
  verified directly; a Linux/WSL build pass and the actual CI run are recorded
  in this phase's own report as still open (WSL toolchain not present in this
  environment - see `TODO.md`/the phase report for exactly what remains).

### Roadblock cleared - the BACnet/SC transport spike, now history

The v1.0.0 release (below) shipped with the BACnet/SC WebSocket/TLS transport
as a **documented stub**, per the task's original constraint: no heavyweight
TLS/crypto dependency without stopping to report it as a roadblock first. That
roadblock was explicitly **cleared by the user**, who approved **libwebsockets
+ OpenSSL via vcpkg**, both transport roles (hub-function listener and hub
connector), and self-signed lab test certificates generated by a setup
script. Phases 2-5 (this entry) are that approved work: a real listener, a
real connector, real certificate File objects, and this documentation/CI/
version-bump pass. The stack-ownership finding itself (the CAS BACnet Stack
owns the BACnet/SC *protocol*, not the *transport* - see `main.cpp`'s file
header) was correct then and remains correct now; only the transport
implementation changed, from stub to real.

## [1.0.0] - unreleased

### Added

- First implementation of the **B-SCHUB (BACnet Secure Connect Hub)** profile
  example, seeded from [B-ASC](https://github.com/chipkin/BACnetProfileExample-B-ASC-CPP).
  Implements **DS-RP-B, DM-DDB-B, DM-DOB-B, DM-DCC-B, NM-SCH-B**: ReadProperty,
  Who-Is/I-Am, Who-Has/I-Have, DeviceCommunicationControl, and a **BACnet/SC hub
  function**.
- Device 389022 "Rainbow", with the series' base object set: Analog Input 1
  "Bronze", Binary Input 1 "Emerald", Multi-State Input 1 "Hot Pink" (all
  read-only - this profile does not require DS-WP-B, so no commandable outputs
  are present, unlike B-ASC).
- **Network Port 1 "Vermilion"** (BACnet/IP, UDP 47808) - kept fully active so
  the example stays discoverable over plain BACnet/IP.
- **Network Port 2 "Vermilion 2"** (BACnet/SC, `Network_Type = secureConnect
  (11)`) - the BACnet/SC hub function: `BACnetStack_SetBACnetSCUuid`,
  `BACnetStack_AddBACnetSCAcceptUri`, `BACnetStack_SetBACnetSCHubFunctionConfig`
  (enabled, `wss://` accept URI), and all five SC transport/status callbacks
  registered.
- Pinned to CAS BACnet Stack `6.x` @ `abd4cee1` (6.0.21), linked as a prebuilt
  **STATIC** library (`CAS_BACNET_STACK_LINK=STATIC`), built by
  `tools/build-stack-static.sh`. `common/` vendored from B-SS-CPP at 2.5.0.
- `docs/objects.json` + the generated `## Objects and properties` README block
  (zero ⚠ rows), the series profile-table block, and a footprint placeholder
  (filled at first release).
- `.github/workflows/release.yml` (the series Wave-0 template, names
  substituted for `BACnetExampleBSCHUB` / `B-SCHUB`).

### Spike finding - BACnet/SC transport ownership (this repo is canonical for F-SC)

- **The CAS BACnet Stack owns the BACnet/SC protocol (handshake, connection
  state machines, framing, certificate bookkeeping) but NOT the WebSocket/TLS
  transport** - read directly from `CASBACnetStackDLL.h`'s doc comments
  (`BACnetStack_RegisterCallbackInitiateWebsocket`: *"The stack implements no
  WebSocket or TLS itself."*) and confirmed against
  `submodules/cas-bacnet-stack/docs/CAS BACnet Stack - BACnet SC Manual_v6.md`.
  The application must supply the transport via four callbacks
  (`InitiateWebsocket`/`DisconnectWebsocket`/`SCStartListening`/
  `SCStopListening`) and report status back through
  `BACnetStack_SetBACnetSCWebSocketStatus`.
- Per the task's constraint (no heavyweight TLS/crypto vendoring without
  stopping to report it as a roadblock; a dependency-free `common/`
  WebSocket helper is acceptable only if genuinely small and dependency-free),
  and because BACnet/SC's accept URIs mandate the `wss://` (TLS) scheme, this
  example did **not**, at this version, implement the transport. `main.cpp`
  section 2c registered honest stub callbacks that logged what the stack asked
  for and declined, rather than a partial, non-conformant (no-TLS)
  implementation. **This was superseded in v1.1.0 above** once the user
  cleared the roadblock - see "Roadblock cleared" above.
- **What was real and stack-verified even at v1.0.0:** the hub function's
  BACnet-level configuration (UUID, accept URI, `SetBACnetSCHubFunctionConfig`
  enabled) all succeeded at runtime, and the stack's own state machine called
  back into this example (`CallbackSCStartListening`) asking to listen on the
  configured `wss://` URI - proven by running the example, not just by reading
  the code.

### Verified

- STATIC build, zero warnings from `main.cpp`/`common/`.
- Smoke test: `--port`, `--help`, `--version` all exit 0 and print the expected
  version/ready lines; `--deviceID` overrides the announced instance.
- Real BACnet/IP wire verification with a live BACnet client: Who-Is → I-Am from
  instance 389022; ReadProperty of Device `Object_Name`/`Vendor_Identifier`/
  `Model_Name`; Analog Input 1 `Present_Value` = 21.5; Network Port 2
  `Object_Name` = "Vermilion 2" and `Network_Type` = 11 (`secureConnect`).
- **Not verified at v1.0.0** (since resolved - see the [1.1.0] entry above):
  an actual BACnet/SC node connecting to this hub and reading its Device
  object over that connection - at the time this required a working
  WebSocket/TLS transport (not yet implemented) and a second SC-capable
  process, neither of which was available/attempted in that session. Flagged,
  not faked, at the time.
