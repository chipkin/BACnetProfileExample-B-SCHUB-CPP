# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **BACnet/SC hub-function (listener) transport is now real**, not a stub:
  `sc_transport/ScTransport` (libwebsockets + OpenSSL, mutual TLS 1.3,
  subprotocol `hub.bsc.bacnet.org`) and `sc_transport/ScTransportRouter` (the
  stack&lt;-&gt;transport glue, dispatching by Network Port instance) implement
  Phase 2 ("Listener") of `docs/bacnet-sc-transport-plan.md`. `main.cpp`'s
  four transport callbacks (section 2c) are thin forwards to `ScTransport`;
  `CallbackSCStartListening`/`CallbackSCStopListening` are fully real.
  `scripts/generate-test-certs.cmake` (`cmake --build build --target
  test-certs`) generates lab-only self-signed certs under `certs/`
  (gitignored). New CLI options `--sc-port` (default 47819) and
  `--sc-cert-dir` (default `./certs`).
- Verified (V1-V3 in the plan): `tests/sc/hub_listener_test.py` (TLS 1.3 +
  subprotocol negotiation, the required negative cases, and a hand-built
  BVLC-SC Connect-Request getting a Connect-Accept back) and a real peer
  (`BACnetSCCli.exe`, `Role=node`) completing Who-Is/I-Am/ReadProperty
  discovery of this device over BACnet/SC.
- Removed the Phase 1 spike (`sc_transport_spike.h/.cpp`, the `--sc-spike` CLI
  hook) now that the real `sc_transport/` classes replace it.
- **BACnet/SC hub-connector (initiate) transport is now real**, not a stub:
  `ScTransport::Connect()`/`Disconnect()` implement Phase 3 ("Connector") of
  `docs/bacnet-sc-transport-plan.md` - one client `lws_context` per
  connection, subprotocol `hub.bsc.bacnet.org`, mutual TLS 1.3, the same
  binary-frame/reassembly/1497-byte-ingress rules the listener half already
  enforced (shared via a new `HandleIncomingFragment` helper). No
  auto-reconnect: the stack owns every retry timer (plan fact 7) - this class
  only dials when asked. `CallbackInitiateWebsocket`/
  `CallbackDisconnectWebsocket` in `main.cpp` are now real forwards. New CLI
  options `--sc-hub-uri <wss://...>` (turns the connector role on; off by
  default) and `--sc-failover-uri` (optional), wired to
  `BACnetStack_SetBACnetSCHubConnectorForNetworkPort`.
- Verified (V4-V5 in the plan): `tests/sc/fake_hub_server.py` (a hand-built
  mutual-TLS fake hub - Connect-Request/Connect-Accept exchange, `Connected`
  status, then `Disconnected` on the fake hub's own close, with the STACK -
  not `ScTransport` - confirmed to be the one re-dialing afterwards) and a
  real hub (`BACnetSCCli.exe`, `Role=hub`, `AllowLegacyConnectRequestsWithoutHello=false`)
  - the example's own hub-connector state machine reaches
  `HubConnectorState_ConnectedPrimary`, independently confirmed by the real
  hub's own log decoding the example's Connect-Request.
- **4 read-only File objects** (Phase 4 of `docs/bacnet-sc-transport-plan.md`):
  File 1 "Ivory" (operational certificate, `certs/hub.crt`), File 2 "Ivory 2"
  (certificate signing request, `certs/hub.csr`), and File 3/4 "Ivory 3"/"Ivory
  4" (the 2 required issuer-certificate slots, both `certs/ca.crt` in this lab
  setup), all stream-access via `BACnetStack_AddFileObject` and bound to
  Network Port 2 with `BACnetStack_SetBACnetSCCertificateFileObjects`.
  `main.cpp`'s new `CallbackReadFile` (section 2d) serves the real bytes of
  each file straight off disk under `--sc-cert-dir` - never `certs/hub.key`,
  which has no File object at all. `RegisterCallbackValidateBACnetSCOperationalCertificate`/
  `RegisterCallbackGenerateBACnetSCCertificateSigningRequest` are also
  registered, for documentation/completeness only - both have zero call sites
  in this stack build (plan fact 10 / stack item S6), so registering them
  provides no real certificate-validation security. AtomicReadFile
  (`SERVICE_ATOMIC_READ_FILE`) is now enabled - its own confirmed service, not
  implied by adding a File object. No WriteFile: this device stays read-only.
- Verified (V6 in the plan), over BACnet/IP with a hand-built `bacpypes3`
  client (`tests/sc/file_object_test.py`): `AtomicReadFile(File 1)` returns
  the bytes of `certs/hub.crt` byte-for-byte; Network Port 2's
  `Issuer_Certificate_Files` has exactly 2 entries; every File object (1-4)
  was enumerated and read, and none served `certs/hub.key`.

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
  series (`cmake -B build -S .` / `cmake --build build --config Release`), with
  no `tools/build-stack-static.sh` pre-step and no `-DCAS_BACNET_STACK_LINK=...`
  flag. `.github/workflows/release.yml` drops the static-library cache/build
  steps and the matrix `lib:` entries, configures without a link-mode flag,
  asserts `CAS_BACNET_STACK_LINK=SOURCE`, records `"link_mode": "SOURCE"` in
  `metrics-*.json`, and packages `TUTORIAL.md` / `docs/PICS.md` into the
  release artifact. The v1.0.0 footprint numbers in README.md were measured
  from the old STATIC build; the next release refreshes them under SOURCE.

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
  example does **not** implement the transport. `main.cpp` section 2c
  registers honest stub callbacks that log what the stack asked for and
  decline, rather than a partial, non-conformant (no-TLS) implementation.
  See `TODO.md` for exactly what a real transport implementation needs to add.
- **What is real and stack-verified:** the hub function's BACnet-level
  configuration (UUID, accept URI, `SetBACnetSCHubFunctionConfig` enabled) all
  succeed at runtime, and the stack's own state machine calls back into this
  example (`CallbackSCStartListening`) asking to listen on the configured
  `wss://` URI - proven by running the example, not just by reading the code.

### Verified

- STATIC build, zero warnings from `main.cpp`/`common/`.
- Smoke test: `--port`, `--help`, `--version` all exit 0 and print the expected
  version/ready lines; `--deviceID` overrides the announced instance.
- Real BACnet/IP wire verification with a live BACnet client: Who-Is → I-Am from
  instance 389022; ReadProperty of Device `Object_Name`/`Vendor_Identifier`/
  `Model_Name`; Analog Input 1 `Present_Value` = 21.5; Network Port 2
  `Object_Name` = "Vermilion 2" and `Network_Type` = 11 (`secureConnect`).
- **Not verified:** an actual BACnet/SC node connecting to this hub and
  reading its Device object over that connection - this requires a working
  WebSocket/TLS transport (not implemented - see above) and a second
  SC-capable process, neither of which was available/attempted in this
  session. Flagged, not faked - see README.md "BACnet/SC support".
