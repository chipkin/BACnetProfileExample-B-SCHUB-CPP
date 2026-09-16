# AGENTS.md

Guidance for AI coding agents working in this repository. See
<https://agents.md/> for the format. Human contributors should read
[README.md](README.md) first, then [TUTORIAL.md](TUTORIAL.md).

## What this project is

A **tutorial** C++ example that implements the BACnet **B-SCHUB (BACnet Secure
Connect Hub)** device profile using the CAS BACnet Stack. It is one of a
series - one git repo per BACnet profile - and builds on the B-ASC
(Application Specific Controller) example, replacing its WriteProperty/
commandable-outputs delta with a **BACnet/SC hub function** (NM-SCH-B). The top
priority is that the code reads like a tutorial a customer can learn from and
copy-paste. Favour clarity over cleverness.

**This repository is the series' spike for BACnet/SC (canonical for F-SC).**
Read [README.md "BACnet/SC support"](README.md#bacnetsc-support-read-this-first)
and [TODO.md](TODO.md) before touching anything SC-related: the BACnet/SC
*protocol* configuration is real and runs; the WebSocket/TLS *transport*
underneath it is a documented stub, not an oversight.

## Layout

This repository is self-contained:

- `main.cpp` - the example device.
- `common/` - the shared helper, vendored in-repo (not referenced via a path
  outside the repository).
- `README.md` - what this example is. Keep it short and about THIS example only.
- `TUTORIAL.md` - how to extend and review the example (including what a real
  BACnet/SC transport needs). Long-form material that would bloat the README
  belongs here.
- `docs/PICS.md` - the Protocol Implementation Conformance Statement. Its
  objects-and-properties section is GENERATED from `docs/objects.json`; do not
  hand-edit between the `OBJECTS-PROPERTIES` markers.
- `docs/objects.json` - the input to that generator. Update it in the same change
  as any `main.cpp` change that adds an object or a `GetProperty*` branch.
- `submodules/cas-bacnet-stack/` - the **CAS BACnet Stack** as a git submodule
  (private). After cloning, run `git submodule update --init --recursive`.

The `PROFILE-TABLE` block in README.md is also generated, from the example-series
repository's `docs/profile-table.md`. Edit it there, not here.

## Build

Plain CMake, identical on every platform, in the adapter's default SOURCE mode
(the stack's sources are compiled into the executable - no prebuilt library, no
DLL, no per-platform pre-step):

```bash
git submodule update --init --recursive   # once, if not cloned with --recursive
cmake -B build -S .
cmake --build build --config Release
```

The first build compiles the whole stack (~600 files) and takes a few minutes;
rebuilds after that are incremental and fast. Use `-D CAS_STACK_DIR=...` only if
your stack lives outside the bundled submodule. Do not reintroduce a link-mode
flag or a series-root build script into the documented build: a customer
downloads this repository on its own and must be able to build it with the two
commands above.

## Run

```bash
./build/BACnetExampleBSCHUB [--port 47808] [--deviceID 389022]   # Linux/macOS
.\build\Release\BACnetExampleBSCHUB.exe [--port 47808] [--deviceID 389022]   # Windows
```

Interactive keys while running: `h` help, `q` quit, up/down nudge Analog Input 1.

## Conventions

- Device is named "Rainbow"; objects use the series' colour names; vendor id 389.
- Implement **only** the services and objects the B-SCHUB profile requires -
  but expose **every required property** of each object for Protocol_Revision
  24. No WriteProperty, no commandable outputs - this profile does not require
  DS-WP-B.
- Two Network Port objects: 1 "Vermilion" (BACnet/IP - keep this fully
  functional, it is the example's fallback discovery path) and 2 "Vermilion 2"
  (BACnet/SC, `Network_Type = secureConnect (11)`, a **local** constant in
  `main.cpp` - not added to `common/`, see below).
- DeviceCommunicationControl (DM-DCC-B): the stack runs the enable/disable state
  machine; the `DeviceCommunicationControl` callback just validates `DCC_PASSWORD`
  and logs. The deprecated plain `disable` (1) is rejected by the stack at
  Protocol_Revision >= 20 - only `enable` (0) and `disable-initiation` (2) apply.
  This callback has no fallback error code: it must set `*errorCode` on every
  `false` return.
- BACnet/SC (NM-SCH-B): `BACnetStack_SetBACnetSCUuid` (once, before any SC
  data link starts), `BACnetStack_AddBACnetSCAcceptUri` (must be called BEFORE
  enabling the hub function), then `BACnetStack_SetBACnetSCHubFunctionConfig`.
  The four transport callbacks (`main.cpp` section 2c) are **stubs by design**:
  do not "complete" them with a fake success path - either implement a real
  WebSocket/TLS transport (see TODO.md for what that needs) or leave them
  honestly declining.
- Every `GetProperty*` callback ends with `uint32_t* errorCode`. Leave it alone
  on a catch-all decline (the stack's decline-and-fabricate default answers
  required properties this app does not serve); set it only where this device
  knows the read is wrong (`State_Text` out of range is the one case here).
- Match the surrounding code style: `const`-correct parameters, check every stack
  return value, keep `main.cpp` linear and well-commented.
- **Never edit `common/` in this repo alone** - it is a vendored copy shared by
  every example in the series, with its own version (`COMMON_VERSION`) and
  changelog (`common/CHANGELOG.md`). To change it: edit `common/` in
  `BACnetProfileExample-B-SS-CPP` first, bump the version, add a changelog
  entry, open and merge that PR, then re-copy `common/` into every example
  repository (`tools/sync-common.sh`). This repo did not need a `common/`
  change - the local `NETWORK_PORT_NETWORK_TYPE_SECURE_CONNECT` constant lives
  in `main.cpp`, not `common/`, for exactly that reason.

## How to verify a change

There are no unit tests; verification is behavioural:

1. Build, then run one instance on a clear UDP port.
2. With a BACnet client (e.g. `bacpypes3`, or the CAS BACnet Explorer), send
   **Who-Is** and confirm **I-Am** from the device instance over BACnet/IP.
3. **ReadProperty** every required property of every object and confirm the
   values; confirm `Protocol_Revision` is 24 and `Object_List` lists all
   objects, including both Network Ports; confirm Network Port 2's
   `Network_Type` reads back `11` (secureConnect).
4. **DeviceCommunicationControl**: confirm `disable-initiation` and `enable`
   SimpleACK, the deprecated `disable` is rejected (service-request-denied), and a
   wrong password (if `DCC_PASSWORD` is set) is rejected (password-failure).
5. **BACnet/SC**: confirm the SC configuration calls all return success at
   start-up and that the console prints the `CallbackSCStartListening` line
   once. An actual SC node connecting is **not** verifiable without a real
   transport implementation (see TODO.md) - do not claim it works without one.
6. If you changed the objects or their properties, regenerate `docs/PICS.md`
   (`python tools/gen-objects-properties.py BACnetProfileExample-B-SCHUB-CPP`
   from the series root) and confirm no row comes out flagged with ⚠.

## Releasing

Bump `APP_VERSION` in `main.cpp` and add an entry to [CHANGELOG.md](CHANGELOG.md),
then tag `vX.Y.Z`. The GitHub Actions workflow builds and publishes the release.

## License

The example source code is dedicated to the public domain under
[CC0-1.0](LICENSE). The CAS BACnet Stack is a separate, commercially licensed
product and is not covered by that dedication.
