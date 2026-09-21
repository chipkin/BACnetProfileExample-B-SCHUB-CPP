# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
