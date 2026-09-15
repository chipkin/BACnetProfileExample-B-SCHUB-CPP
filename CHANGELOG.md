# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  `tools/build-stack-static.sh`. `common/` vendored from B-SS-CPP at 2.2.0.
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
- Real BACnet/IP wire verification with `bacpypes3`: Who-Is → I-Am from
  instance 389022; ReadProperty of Device `Object_Name`/`Vendor_Identifier`/
  `Model_Name`; Analog Input 1 `Present_Value` = 21.5; Network Port 2
  `Object_Name` = "Vermilion 2" and `Network_Type` = 11 (`secureConnect`).
- **Not verified:** an actual BACnet/SC node connecting to this hub and
  reading its Device object over that connection - this requires a working
  WebSocket/TLS transport (not implemented - see above) and a second
  SC-capable process, neither of which was available/attempted in this
  session. Flagged, not faked - see README.md "BACnet/SC support".
