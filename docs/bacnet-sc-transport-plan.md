# Plan: real BACnet/SC transport (WebSocket + TLS) for BACnetProfileExample-B-SCHUB-CPP

## Context

`BACnetProfileExample-B-SCHUB-CPP` configures a real, stack-verified BACnet/SC hub function, but its four
transport callbacks (`main.cpp` section 2c) log and decline, so no SC node can ever connect. The user has
cleared the "no heavyweight TLS dependency" roadblock: **libwebsockets + OpenSSL via vcpkg**, **both roles**
(hub function listener + hub connector), **self-signed test certs from a setup script**. Outcome: an external
BACnet/SC node connects over `wss://` with mutual TLS 1.3, and reads the hub's Device object through it — the
original task card's verification criterion (`runbook-update-examples.md:625`).

All paths relative to `C:\dev\chipkin\cas-bacnet-stack-examples\BACnetProfileExample-B-SCHUB-CPP\` unless noted.

## Facts established during planning (verified in source — these override the prompt/manual where they differ)

1. **Subprotocol is `hub.bsc.bacnet.org`** (135-2024 AB.7.1; stack `_spec/BACnetSC/docs/4.2_BACnetSC-checklist.md:432-441`
   SC-REQ-063; BACnetSCCli `ExampleHubSupport.h:63`). plugfest-example's `hub.bacnet.org` is **wrong** — it only
   passed against its own echo server. Do not copy that string.
2. **Accepted inbound connections are identified by a connection string the app mints**:
   `<configured accept URI>|client=<unique suffix>` (`source/BACnetDataLinkSC.cpp:899-914` `DoesConfiguredUriMatch`;
   test `tests/BACnetSC_Tests/TestBACnetInterface_BACnetSC.cpp:4484-4519`). There is no "client connected" API: the
   stack learns of a peer from its first frame (Connect-Request). Report source = `uri|client=N`, destination = bare
   accept URI (the form the stack's own tests use). Every later egress to that peer arrives in SendMessage with that
   exact string → pure map lookup. Max 255 bytes, no `;` in it, never reuse a string across sockets.
3. **WebSocket status enum is Connecting=1, Connected=2, Disconnected=3, Error=4** (`source/BACnetSCConstants.h:93-99`).
   The manual (§19, App. D.3) says Disconnected=1 — wrong. For an accepted peer only Disconnected/Error matter
   (they evict the peer from the hub table — **mandatory on every socket death**, else stale peers).
4. **SC SendMessage must return exactly `messageLength`** on success (#1569; `BACnetSCHubFunctionManager.cpp:432,460`,
   `BACnetSCHubConnector_Outgoing.cpp:232,296`), 0 if the socket is unknown/closed.
5. **Callbacks: `...MessageForPort` with `networkPortInstance`** (no `networkType`). Inbound SC must report the real
   SC Network Port instance (2) (`BACnetDataLinkLayer.cpp:416-443`). Outbound SC sites currently pass the literal
   `NetworkType_SC` (=2) rather than the real instance — this example's `SC_NETWORK_PORT_INSTANCE` is already 2, so
   dispatch-by-instance is correct under both readings. **Keep it 2** and note why in a comment.
6. **Re-entrancy is unsupported**: never call `BACnetStack_*` from inside a stack callback. `InitiateWebsocket` return is
   discarded for the hub connector; `SCStartListening` return is honoured and retried every Tick while false.
   `SCStartListening` can also fire synchronously from inside `BACnetStack_AddBACnetSCAcceptUri`. `DisconnectWebsocket`
   may be called with an accepted-peer (`|client=`) string, not just outbound URIs.
7. **Stack owns all timers** (heartbeat, reconnect, failover). The transport must not auto-reconnect.
8. **Ingress ceiling 1497 bytes** (`BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH`); larger frames are discarded by the stack.
9. `lws_service()` ignores `timeout_ms` and **blocks** until an event (plugfest gotcha G1).
10. Validate-cert / generate-CSR callbacks have **zero call sites** in the stack. Issuer File slots must be exactly 2.
11. Licensing: plugfest-example files have no licence header (Chipkin-owned, private) → adapt freely into CC0 with a
    changelog note. **BACnetSCCli sources carry the CAS proprietary header → behavioural reference only, re-implement,
    copy nothing.** libwebsockets is MIT, OpenSSL 3 is Apache-2.0 → record both in README + AGENTS.md licence sections.
12. Series gates (`../tools/check-series.sh`): check 1 `common/` byte-identical (do not edit), check 6 every
    `BACnetStack_*` setup return checked, check 11 `release.yml` must equal B-SS's modulo names (**will fail** → needs
    an exemption), check 4d/4e version agreement, check 10 objects block. Runbook §0: present-tense docs only, history
    lives in `CHANGELOG.md`. Precedent for an extra top-level folder: `BACnetProfileExample-B-OD-CPP/third_party/`.

## Architecture

New folder **`sc_transport/`** (example-specific, pulls a dependency no sibling needs; `common/` untouched).
Single-threaded; all shared state is plain queues owned by the main thread.

```
main loop:  BACnetStack_Tick();  ScTransport::Service();  PollKey();  Sleep(1)
```

### `sc_transport/ScTransport.h/.cpp` — libwebsockets wrapper (no stack calls inside lws callbacks)
- `struct ScTlsFiles { caCert, cert, key }` (PEM paths). `Configure(tls, acceptSubprotocol="hub.bsc.bacnet.org")`.
- **Listener** `StartListening(uri)` → parse `wss://host:port/path`; create a server `lws_context`:
  `info.port`, `info.iface` (NULL for 0.0.0.0), `ssl_cert_filepath`, `ssl_private_key_filepath`, `ssl_ca_filepath`,
  options `LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT`,
  TLS 1.3 only via `ssl_options_set = SSL_OP_NO_TLSv1|..._1|..._2`, `info.user = this`
  (`lws_context_user(lws_get_context(wsi))`, no static singleton). Returns false (logged once) if cert files are
  missing or the bind fails → stack retries. `StopListening(uri)` closes peers, destroys the context.
  Callbacks: `ESTABLISHED` (mint `uri|client=<counter>`, register in `map<string,Conn>` + `map<lws*,string>`),
  `RECEIVE` (reject non-binary with `LWS_CLOSE_STATUS_UNACCEPTABLE_OPCODE`; reassemble with
  `lws_is_final_fragment` + `lws_remaining_packet_payload`; drop+log frames >1497; push `{connStr, destUri, bytes}`
  to the rx queue), `SERVER_WRITEABLE` (one frame, `LWS_PRE`, `LWS_WRITE_BINARY`, short write → close),
  `CLOSED` (erase, push status event Disconnected/Error). Any URL path accepted; only the hub subprotocol offered.
- **Connector** `Connect(uri)` → one client `lws_context` (`CONTEXT_PORT_NO_LISTEN`, `client_ssl_ca/cert/private_key_filepath`,
  `ssl_client_options_set` for TLS 1.3 only), `lws_client_connect_via_info` with `protocol="hub.bsc.bacnet.org"`,
  `LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK` (CA chain still verified; SC certs identify devices, not
  hosts — document this). Keyed by the exact URI the stack passed. Callbacks `CLIENT_ESTABLISHED` → status Connected(2);
  `CLIENT_CONNECTION_ERROR` → Error(4); `CLIENT_CLOSED` → Disconnected(3); `CLIENT_RECEIVE` (same reassembly/binary
  rules), `CLIENT_WRITEABLE`. `Disconnect(connStr)` works for both outbound URIs and `|client=` peers. No auto-reconnect.
  Pattern source: `../plugfest-example/src/datalink/ScWebSocketClient.cpp` (fix its gaps: no reassembly, no text-frame
  rejection, hard-coded error code 0, wrong subprotocol).
- `Send(connStr, data, len)` → enqueue + `lws_callback_on_writable`; returns false if unknown/closed.
- `PopReceived(frame)`, `PopStatusEvent(evt)` — status events are **queued, never sent from lws callbacks** (lws can
  fire callbacks synchronously inside `Connect`, which runs inside `Tick()` → re-entrancy, fact 6).
- `Service()` → non-blocking pump of each live context. **Spike-gated choice (step 1 of execution):**
  (a) `lws_cancel_service(ctx); lws_service(ctx, 0);` (documented API; the cancel makes the poll return immediately),
  else (b) `lws_service(ctx, -1)` (lws 4.x treats negative as zero-wait; undocumented), else (c) fallback: a worker
  thread running `lws_service` with a mutex around the three queues and `lws_cancel_service` on enqueue (BACnetSCCli's
  shape). Queue-only interface means (c) changes nothing outside this class. Route lws logs through `lws_set_log_level`.

### `sc_transport/ScTransportRouter.h/.cpp` — stack ↔ transports glue
Per the user's direction: dispatch on the `networkPortInstance` parameter of
`BACnetStack_RegisterCallbackReceiveMessageForPort` / `...SendMessageForPort`.
- `common/`'s own callbacks are file-private and UDP-only, and the stack holds one pointer per callback, so the router
  registers its own pair **after** `CASExampleHelper::RegisterCommonCallbacks()` (which still supplies GetSystemTime)
  and owns a `SimpleUDP` (public class in `common/SimpleUDP.h`) for Network Port 1 instead of `SetupUDP()`.
  Replicates the 6-byte `ip[4]+port[2]` connection string and the `RX/TX` log lines from
  `common/CASExampleHelper.cpp:111-214`. `common/` stays byte-identical.
- Receive: alternate IP-first / SC-first each Tick (one frame per Tick; avoids SC starvation). SC frame → source =
  conn string, destination = accept URI (empty for connector frames), `*networkPortInstance = SC port (2)`.
  IP → `*networkPortInstance = 1`.
- Send: `networkPortInstance == IP port` → UDP; `== SC port` → `ScTransport::Send`, return `messageLength` or 0.
- `DrainStatusEvents()` called from the main loop after `Service()` →
  `BACnetStack_SetBACnetSCWebSocketStatus(uri, len, status, closeCode)`; a `false` return for a peer the stack has
  not registered yet is normal, not logged as an error.
- I-Am at start-up: `CASExampleHelper::SendIAm` needs common's binding table → router provides its own
  `SendIAm(device, port)` wrapper around `BACnetStack_SendIAm` using `CASExampleHelper::GetLocalIPv4` (same
  local-broadcast computation, `CASExampleHelper.cpp:555-586`).

### `main.cpp` changes
- Section 2c becomes "BACnet/SC transport (NM-SCH-B)": the four callbacks are thin forwards to `ScTransport`
  (copy the stack-owned URI into `std::string`; `SCStartListening` returns the real result). State-change callback
  guards NULL URI.
- New CLI args parsed in `main.cpp` (common's `--help` cannot list them → print an "SC options" block from `main.cpp`
  when `--help` is present, before delegating): `--sc-port <n>` (default 47819), `--sc-cert-dir <dir>` (default
  `./certs`), `--sc-hub-uri <wss://…>` and optional `--sc-failover-uri` (hub connector; **off unless given**, because
  the stack rejects an empty primary URI — then `BACnetStack_SetBACnetSCHubConnectorForNetworkPort(device, 2, vmac…)`).
- Start-up prints cert status; if certs are missing it prints the generate command and carries on (BACnet/IP works,
  listener declines, stack retries — existing CI "ready" smoke test still passes).
- Header comment (lines 33-78) rewritten in present tense; `APP_VERSION` bump; every new `BACnetStack_*` return checked.
- Phase 4 only: 4 read-only File objects via `BACnetStack_AddFileObject`, `RegisterCallbackReadFile` serving
  `hub.crt` / `hub.csr` / `ca.crt` ×2 from the cert dir (**never the key**), `SetBACnetSCCertificateFileObjects`,
  GetProperty branches for their names, the two dead cert callbacks registered with a "not invoked by this stack
  build, not a security control" comment. No WriteFile (device stays read-only).

## Certificates

**`scripts/generate-test-certs.cmake`** run as `cmake -P scripts/generate-test-certs.cmake` (also a
`test-certs` custom target). Rationale: CMake is already a prerequisite on every platform → one script, no bash/
PowerShell twins, no MSYS `/CN=` path mangling (plugfest G16), no `<(…)` process substitution (Appendix B.3 is
bash-only). Finds `openssl` via PATH, then `build/vcpkg_installed/*/tools/openssl`, then Git-for-Windows.
Follows manual Appendix B (ECDSA P-256): `ca.key/ca.crt` (10 y); `hub.key/hub.csr/hub.crt` with
`extendedKeyUsage=serverAuth,clientAuth` + `subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:<hostname>`;
`node.key/node.crt` (clientAuth) for a test peer; runs `openssl verify`; refuses to overwrite unless `-DFORCE=1`.
Output `certs/` → added to `.gitignore` (plus `vcpkg_installed/`). Both consumers read the same files: lws context
(paths) and, in phase 4, the ReadFile callback. Docs state "lab testing only; production must use a real CA".

## Build system
- **`vcpkg.json`** (new): deps `libwebsockets`, `openssl`; `builtin-baseline 04a9d8e5212d01ee1dd9478eadd9caade4f8b0d4`
  (same pin as `../plugfest-example/vcpkg.json` → local binary cache already warm). Executor: check whether the port's
  default features can be trimmed (libuv/brotli not needed) — nice-to-have only.
- **`CMakeLists.txt`**: before `project()`, if `CMAKE_TOOLCHAIN_FILE` is unset and `$ENV{VCPKG_ROOT}` exists, set it
  (keeps the documented two-command build; clear `FATAL_ERROR` with instructions otherwise, unless a system
  libwebsockets is found). On Windows default `VCPKG_TARGET_TRIPLET=x64-windows-static` +
  `CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded$<$<CONFIG:Debug>:Debug>` **set before `add_subdirectory(adapter)`** so the
  stack matches. `find_package(libwebsockets CONFIG REQUIRED)`, `find_package(OpenSSL REQUIRED)`; link bare
  `websockets` (or `websockets_shared` for distro packages), `OpenSSL::SSL OpenSSL::Crypto`; add `sc_transport/*.cpp`
  to the target and to the strict-warnings source set; `test-certs` custom target. Verify `CAS_BACNET_STACK_LINK`
  stays `SOURCE` (CI asserts it).
- README prerequisites: vcpkg (`VCPKG_ROOT`; VS bundles one), first configure builds OpenSSL (~10-15 min once).

## CI (`.github/workflows/release.yml`) — chosen: vcpkg + `actions/cache`, both OSes
Adapt `../plugfest-example/.github/workflows/build.yml:113-137`: `VCPKG_ROOT=$VCPKG_INSTALLATION_ROOT`,
`VCPKG_BINARY_SOURCES=clear;files,<ws>/vcpkg-binary-cache,readwrite`, `actions/cache` keyed
`vcpkg-<os>-hashFiles('vcpkg.json')`, and the **baseline-fetch workaround** (`git -C $VCPKG_ROOT fetch --depth=1 origin
<baseline>` when the runner's clone is older). Pass the toolchain/triplet at configure. After the existing smoke test:
generate certs, start the exe, run `tests/sc/hub_listener_test.py` (setup-python + `pip install websockets`).
Package step also ships `scripts/` and a `THIRD-PARTY-NOTICES.md`.
- **Cost estimate (flag to user, accepted in planning):** cold cache ≈ +12-20 min Windows / +6-10 min Linux; warm
  ≈ +1-2 min each. Cold happens on first run, on `vcpkg.json` change, or after GitHub's 7-day idle cache eviction —
  this workflow only runs on PRs/tags/dispatch, so **evictions will be common; expect cold builds on most release
  runs.** Windows minutes bill 2× on private repos (free if the repo is public). Mitigation option for later: a
  GitHub Packages NuGet binary source (no eviction).
- **Series gate:** `../tools/check-series.sh` check 11 must gain a documented B-SCHUB exemption (compare against the
  template only outside a marked `# SC-TRANSPORT:BEGIN/END` block, or skip with a printed reason). That file is
  outside this repo (the parent folder is not a git repo) — executor makes the edit and tells the user where it lives.

## Files

**New:** `sc_transport/ScTransport.h/.cpp`, `sc_transport/ScTransportRouter.h/.cpp`, `sc_transport/README.md`
(contract summary: facts 2-8, licence note), `scripts/generate-test-certs.cmake`, `vcpkg.json`,
`tests/sc/hub_listener_test.py`, `tests/sc/fake_hub_server.py`, `tests/sc/requirements.txt`, `tests/sc/README.md`,
`THIRD-PARTY-NOTICES.md`.
**Modified:** `main.cpp`, `CMakeLists.txt`, `.gitignore`, `.github/workflows/release.yml`, `README.md` (rewrite
"BACnet/SC support", prerequisites, build, CLI options, "Verify → Over BACnet/SC", what's-in-repo), `TUTORIAL.md`
(§"Implement the BACnet/SC transport for real" → how the transport works / productionising: real CA, cert rotation,
hostname policy), `TODO.md` (item 1 replaced by remaining gaps: see Risks), `CHANGELOG.md` (new version entry; records
that the spike roadblock was cleared by explicit approval — history lives here only), `AGENTS.md` (layout, "stubs by
design" rule at :17-21/:90-96 removed, licence section, build note), `docs/objects.json` + regenerated `docs/PICS.md`
(Network Port 2 note; §7/§9 data link; phase 4: File objects + AtomicReadFile), `../tools/check-series.sh` (check 11
exemption), `../docs/colour-table.md` (phase 4: File-object colour names — series-level decision, confirm with user).

## Execution phases (each ends with a local build + its verification; commits are local only)
0. Branch off `main` (current branch `fix-broken-contact-link` is unrelated). Commit identity per user CLAUDE.md:
   `git -c user.name="SWS-Chipkin" -c user.email="sws-dev@chipkin.com"`, trailer per the session's attribution notice.
1. **Spike**: vcpkg.json + CMake wiring + a 30-line lws context in `main.cpp` scratch to settle the `Service()`
   mechanism (a/b/c) on Windows. Confirm SOURCE mode, static CRT consistency, binary size.
2. **Listener** (`ScTransport` server half + router + cert script) → verify V1-V3.
3. **Connector** (client half + `--sc-hub-uri`) → verify V4-V5.
4. **File objects** (own commit) → verify V6.
5. **Docs, CI, gates, version bump** (`APP_VERSION` 1.0.0 → 1.1.0: new capability; CHANGELOG heading stays
   `- unreleased` until tagged, per check 4e) → V7.
6. **Stop.** Report results. Push / PR / tag only on explicit user permission, each separately.

## Verification
- **V1 TLS/WS handshake (listener):** `tests/sc/hub_listener_test.py` (Python `websockets`, `node.crt`): asserts
  TLS 1.3, subprotocol echo `hub.bsc.bacnet.org`; negative cases: no client cert → handshake refused; TLS 1.2 →
  refused; wrong subprotocol → rejected; text frame → closed with 1003. `openssl s_client -tls1_3` as a bisect aid.
- **V2 protocol through the listener:** test sends a hand-built BVLC-SC Connect-Request (0x06, VMAC+UUID+sizes) and
  asserts a Connect-Accept (0x07) comes back on the same socket; then closes abruptly and asserts the example logs the
  peer eviction (status 3) and `SC_Hub_Function_Connection_Status` no longer lists it.
- **V3 real peer (the task-card criterion):** `C:\dev\chipkin\BACnetSCCli\app\build\Release\BACnetSCCli.exe` as
  `Role=node` (copy `app/config/BACnetSC.localhost.node.config`, point `primaryHubURI` at `wss://127.0.0.1:47819/`
  and cert fields at `certs/node.*` + `ca.crt`): expect Who-Is → I-Am from 389022 and ReadProperty(Device, Object_Name)
  = "Rainbow", `Discovery summary status=PASS`. Then two nodes (node + device role) to prove hub relay between peers.
- **V4 connector dial-out (fast):** `tests/sc/fake_hub_server.py` (mutual-TLS `websockets` server, hub subprotocol):
  run the example with `--sc-hub-uri wss://127.0.0.1:<p>/`; assert it receives a binary Connect-Request; answer with a
  canned Connect-Accept and assert a later Heartbeat-Request or state `ConnectedPrimary` in the example's state-change
  log; kill the server → example logs Disconnected and the **stack** (not the transport) re-dials after its timeout.
- **V5 connector vs real hub:** BACnetSCCli `Role=hub` (`BACnetSC.localhost.hub.config`, `AllowLegacy…=false`) — expect
  hub-connector state `ConnectedPrimary`; optionally a second local instance of this example (`--port 47809 --sc-port
  47820 --deviceID 389099 --sc-hub-uri wss://127.0.0.1:47819/`) dialling the first.
- **V6 File objects:** over BACnet/IP with CAS BACnet Explorer (or BACnetSCCli node): AtomicReadFile of the operational
  cert returns the bytes of `certs/hub.crt`; Network Port 2 `Issuer_Certificate_Files` has exactly 2 entries; the key
  is not readable anywhere.
- **V7 regression + gates:** BACnet/IP Who-Is/ReadProperty still works on 47808 while SC peers are connected (mux
  fairness); `--help/--version`; run without `certs/` → clean message, IP still works; `bash ../tools/check-series.sh`
  and `python ../tools/gen-objects-properties.py BACnetProfileExample-B-SCHUB-CPP --check` pass (zero ⚠ rows); Linux
  build via WSL/CI; CI run on a PR branch only after push permission.

## CAS BACnet Stack changes

**Required by this plan: none.** Everything is implementable against the pinned `6.x @ abd4cee1` (6.0.21) public
surface (`CASBACnetStackDLL.h`) as it stands. The submodule pin is not moved, no stack source is edited, and no
compile option is added (SC + File objects are already compiled in — the example's existing SC setup calls succeed
today; phase 1 re-confirms `BACnetStack_AddFileObject` links before phase 4 depends on it).

**Not required, but the plan leans on stack behaviour that should be fixed or documented upstream.** None of these
block execution; each has a workaround already built into the plan. To be filed as issues on
`chipkin/cas-bacnet-stack` (filing = outward-facing → only with user permission; draft text goes in `TODO.md`):

| # | Stack item | Where | Impact on this example today | Proposed stack change |
|---|---|---|---|---|
| S1 | `\|client=` accepted-peer connection-string convention is undocumented | `source/BACnetDataLinkSC.cpp:899-914`; only tests use it | Load-bearing for the listener; a silent change breaks every hub host app | Document it in the `RegisterCallbackSCStartListening` / `ReceiveMessageForPort` doc comments and the SC manual (docs only) |
| S2 | SC send sites pass literal `NetworkType_SC` (2) as `networkPortInstance`; `GetNetworkPortInstanceForSend()` is never called | `BACnetSCHubConnector_Outgoing.cpp:232,296`, `BACnetSCHubFunctionManager.cpp:432,460`, `BACnetDataLinkSC_PacketProcessing.cpp:360` | None **because** this example's SC port instance is 2. Breaks dispatch-by-instance for any app whose SC port ≠ 2 | Pass the real Network Port instance (code fix). When fixed, this example needs no change |
| S3 | Ingress buffer capped at 1497 bytes vs Annex AB's 1600-octet minimum BVLC | `BACnetStackConstants.h:330`, `BACnetInterface.cpp:219-244` | Hub cannot relay a maximum-size BVLC-SC frame; transport drops+logs >1497 | Size the SC ingress path to `Max_BVLC_Length_Accepted` (code fix; possible B-SCHUB conformance gap) |
| S4 | `SendMessageForPort` doc says "return is a flag"; SC paths require `== messageLength` (#1569) | `CASBACnetStackDLL.h:3907-3923` vs the four sites in S2 | None (router returns exact length) | Fix the doc comment (docs only) |
| S5 | SC manual v6 errors: status enum values (§19, D.3), stale `networkType` signatures (§18.1), stale 6-arg `SetBACnetSCHubFunctionConfig` (D.2), cert callbacks presented as live (§16.4/16.5, D.4, G.2), unguarded NULL-URI `memcpy` (§20), subprotocol names absent, §18.3 hub stub only | `docs/CAS BACnet Stack - BACnet SC Manual_v6.md` | None (plan follows the header) — but every customer hits these | Correct the manual; add a hub-function transport section (this example can be its reference) |
| S6 | Validate-certificate and generate-CSR callbacks have no call site | `BACnetInterface.cpp:9813-9828` | Registered for documentation only; hub cert policy is CA-chain-only in the app | Wire them up or remove them from the header and Appendix G |
| S7 | No backpressure/"accepted, will drain" signal in the send contract | send callback contract | Bounded tx queue + close-on-overflow in the transport | Design question for the stack team; no change requested yet |

If the stack team ships S2 or S3 in a later 6.x, picking it up is a normal pin bump under the series update runbook
(all examples move together — check 3), **out of scope here**.

## Open risks / unresolved questions
1. **`|client=` convention is undocumented** (one function + unit tests). Load-bearing; ask Chipkin stack team to
   document it; pin-bump could break it → covered by V2/V3 in CI.
2. **Outbound `networkPortInstance` is literal 2 for SC** (apparently unmigrated stack call sites;
   `GetNetworkPortInstanceForSend()` unused). Harmless here because the SC port *is* 2; file a stack issue.
3. **1497-byte ingress cap vs AB's 1600-octet BVLC minimum** — a hub cannot relay a maximum-size BVLC through this API.
   Possible B-SCHUB conformance gap in the stack; document in TODO.md, report upstream, do not work around.
4. **Backpressure:** SendMessage must claim the full length at enqueue time; if the socket later fails the frame is
   lost silently. Bound the per-connection tx queue (e.g. 64 frames) and close the socket on overflow.
5. **`lws_service` non-blocking mechanism** unverified on Windows until the phase-1 spike; worker-thread fallback defined.
6. **Hub-side certificate policy** is entirely the app's: CA-chain validation only (no CRL, no UUID-in-SAN binding,
   no hostname check on the connector). State this plainly in README/TUTORIAL; Appendix G's "X.509 validation: Complete"
   must not be echoed.
7. **Status semantics gaps:** whether to report Connected(2) for accepted sockets (returns false pre-Connect-Request —
   plan: don't), and Error(4) vs Disconnected(3) mapping (plan: TLS/handshake failure or abnormal close → 4 with close
   code; clean close → 3).
8. **Does a hub need its own hub connector?** Source shows local delivery inside the hub function
   (`RelayEncapsulatedPacket` `shouldProcessLocally`), so the hub's Device is reachable without one — V3 proves it. If
   V3 fails, fallback is pointing the connector at the hub's own listener.
9. **YABE interop** needs `BACnetStack_SetBACnetSCCompatibilityFlags(0x01)` (Connect-Request without Hello). Plan: leave
   strict, document the flag in TUTORIAL.
10. **Manual v6 has ≥5 errors** (status values, stale signatures incl. `SetBACnetSCHubFunctionConfig`, live-cert-callback
    claims, NULL-URI memcpy). README should cite the header as authoritative; report the list upstream.
11. **File-object colour names** and whether AtomicReadFile changes any claimed BIBB (believed no: service list only) —
    confirm at phase 4 before touching `../docs/colour-table.md`.
12. **CI cache eviction** makes cold vcpkg builds the common case for this low-frequency workflow (see CI section).
13. **Two-command build promise** now holds only with `VCPKG_ROOT` set; AGENTS.md:58-62 wording must be updated rather
    than silently broken.
14. Commit trailer: the prompt says "Claude Sonnet 5", this session's notice says "Claude Fable 5.1" — use whatever the
    executing session's attribution notice says.
