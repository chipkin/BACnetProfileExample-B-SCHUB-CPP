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

**This repository is canonical for F-SC (BACnet/SC in the example series).**
Read [README.md "BACnet/SC support"](README.md#bacnetsc-support-read-this-first)
and [TODO.md](TODO.md) before touching anything SC-related: **both** the
BACnet/SC *protocol* configuration and the WebSocket/TLS *transport*
underneath it are real and verified against real peers - there is no
remaining transport stub in this repository. `TODO.md` still lists genuine,
documented limitations (no hostname check by design, no CRL support, the 1497-byte SC
ingress ceiling); read it before assuming a gap is a bug you should fix here
versus a known limitation to work around or report upstream.

## Layout

This repository is self-contained:

- `main.cpp` - the example device.
- `common/` - the shared helper, vendored in-repo (not referenced via a path
  outside the repository).
- `sc_transport/` - the real BACnet/SC WebSocket+TLS transport
  (`ScTransport`, libwebsockets + OpenSSL via vcpkg) and the stack&lt;-&gt;
  transport glue (`ScTransportRouter`). See `sc_transport/README.md` for the
  wire-level contract (subprotocol, connection-string convention, status
  enum, send/receive semantics) before changing anything in this folder -
  several of its rules come from reading the stack's source, not its manual,
  and are easy to get subtly wrong again.
- `cert_tool.{h,cpp}` - `--generate-certs [n]` / `--add-client-certs [n]` /
  `--cert-label`: the built-in lab certificate generator (a CA, the hub, and
  labeled client certificates, plus `certificates.txt`). It runs before the
  stack starts and exits. `--add-client-certs` must keep signing with the
  existing `ca.crt`/`ca.key`, never a new CA, or running hubs stop trusting
  the new clients.
- `scripts/generate-test-certs.cmake` - generates the lab-only self-signed
  certificate set under `certs/` (gitignored) `sc_transport/` and the File
  objects (`main.cpp` section 2d) both read.
- `tests/sc/` - the BACnet/SC verification scripts
  (`hub_listener_test.py`/`fake_hub_server.py`/`file_object_test.py`) and
  their own README. Re-run the relevant one after any `sc_transport/` or
  BACnet/SC-related `main.cpp` change.
- `vcpkg.json` - pins the `libwebsockets`/`openssl` dependencies (see "Build"
  below).
- `README.md` - what this example is. Keep it short and about THIS example only.
- `TUTORIAL.md` - how to extend and review the example, including how the
  real BACnet/SC transport works and what productionizing it further needs.
  Long-form material that would bloat the README belongs here.
- `docs/PICS.md` - the Protocol Implementation Conformance Statement. Its
  objects-and-properties section is GENERATED from `docs/objects.json`; do not
  hand-edit between the `OBJECTS-PROPERTIES` markers.
- `docs/objects.json` - the input to that generator. Update it in the same change
  as any `main.cpp` change that adds an object or a `GetProperty*` branch.
- `THIRD-PARTY-NOTICES.md` - licence notices for `sc_transport/`'s two
  dependencies (see "Licence" below).
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

**This repository needs `VCPKG_ROOT` set**, unlike most examples in this
series: `sc_transport/`'s BACnet/SC transport depends on `libwebsockets` and
`openssl` (vcpkg manifest mode, `vcpkg.json`), and CMake's toolchain
auto-detection (`CMakeLists.txt`, before `project()`) needs `VCPKG_ROOT` in
the environment to find vcpkg's toolchain file - a Visual Studio Developer
Command Prompt already has it; elsewhere, install vcpkg and set it yourself.
The first configure/build after a `vcpkg.json` change (or a totally clean
`build/`) also has to compile OpenSSL from source the first time - budget
~10-15 minutes for that, on top of the stack's own ~600-file compile; vcpkg
caches the result, so it is a one-time cost per machine/toolchain, not per
build.

The first build compiles the whole stack (~600 files) and takes a few minutes;
rebuilds after that are incremental and fast. Use `-D CAS_STACK_DIR=...` only if
your stack lives outside the bundled submodule. Do not reintroduce a link-mode
flag or a series-root build script into the documented build: a customer
downloads this repository on its own and must be able to build it with the two
commands above (plus `VCPKG_ROOT` set, as above).

## Run

```bash
./build/BACnetExampleBSCHUB [--port 47808] [--deviceID 389022]   # Linux/macOS
.\build\Release\BACnetExampleBSCHUB.exe [--port 47808] [--deviceID 389022]   # Windows
```

Interactive keys while running: `h` help, `q` quit, up/down nudge Analog Input 1.

## Conventions

- Device is named "Chipkin Example B-SCHUB"; objects use the series' colour names; vendor id 389.
- Implement **only** the services and objects the B-SCHUB profile requires -
  but expose **every required property** of each object for Protocol_Revision
  24. No WriteProperty, no commandable outputs - this profile does not require
  DS-WP-B.
- Two Network Port objects: 1 "BACnet IP" (BACnet/IP - keep this fully
  functional, it is the example's fallback discovery path) and 2 "BACnet SC"
  (BACnet/SC, `Network_Type = secureConnect (11)`, a **local** constant in
  `main.cpp` - not added to `common/`, see below).
- DeviceCommunicationControl (DM-DCC-B): the stack runs the enable/disable state
  machine; the `DeviceCommunicationControl` callback just validates
  `g_dccPassword` (from `--dcc-password`, `common/` 2.6.0's `ParseDccPasswordArg`)
  and logs. The deprecated plain `disable` (1) is rejected by the stack at
  Protocol_Revision >= 20 - only `enable` (0) and `disable-initiation` (2) apply.
  This callback has no fallback error code: it must set `*errorCode` on every
  `false` return.
- BACnet/SC (NM-SCH-B): `BACnetStack_SetBACnetSCUuid` (once, before any SC
  data link starts), `BACnetStack_AddBACnetSCAcceptUri` (must be called BEFORE
  enabling the hub function), then `BACnetStack_SetBACnetSCHubFunctionConfig`.
  The four transport callbacks (`main.cpp` section 2c) are **real, thin
  forwards to `sc_transport/ScTransport`** - not stubs. If you touch them,
  re-run `tests/sc/hub_listener_test.py` (and `fake_hub_server.py` if you
  touched the connector half) afterward; do not silently reintroduce a fake
  success path or a decline-and-log stub - either keep the real transport
  behaviour intact or, if you deliberately need to strip it back out for some
  reason, say so explicitly in the commit/changelog rather than leaving it
  looking real while quietly not working.
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
   wrong password (if `--dcc-password` was given) is rejected (password-failure).
5. **BACnet/SC**: confirm the SC configuration calls all return success at
   start-up and that the console prints the `CallbackSCStartListening` line
   once, then run `tests/sc/hub_listener_test.py` (listener - always
   applicable) and, if you touched the connector, `tests/sc/fake_hub_server.py`
   (`--sc-hub-uri`). Both transport roles are real; verify against them, do
   not claim BACnet/SC behaviour works from the configuration calls
   succeeding alone.
6. If you changed the objects or their properties, regenerate `docs/PICS.md`
   (`python tools/gen-objects-properties.py BACnetProfileExample-B-SCHUB-CPP`
   from the series root) and confirm no row comes out flagged with ⚠.

## Releasing

Bump `APP_VERSION` in `main.cpp` and add an entry to [CHANGELOG.md](CHANGELOG.md),
then tag `vX.Y.Z`. The GitHub Actions workflow builds and publishes the release.

## License

The example source code is dedicated to the public domain under
[CC0-1.0](LICENSE). The CAS BACnet Stack is a separate, commercially licensed
product and is not covered by that dedication. Building this example also
links two third-party dependencies via vcpkg (never vendored into this
repository): **libwebsockets** (MIT) and **OpenSSL 3** (Apache-2.0), both used
by `sc_transport/`. See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) and
[README.md "Licence"](README.md#licence) for the full notices. If you add
another dependency to `vcpkg.json`, add its licence to both places in the same
change.
