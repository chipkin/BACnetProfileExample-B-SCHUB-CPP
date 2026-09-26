# AGENTS.md

Guidance for AI coding agents working in this repository. See
<https://agents.md/> for the format. Human contributors should read
[README.md](README.md) first, then [TUTORIAL.md](TUTORIAL.md).

## What this project is

A C++ example that implements the BACnet **B-SCHUB (BACnet Secure Connect
Hub)** device profile using the CAS BACnet Stack. It is released to customers
both as a working hub (prebuilt binaries on GitHub Releases) and as source to
learn from and copy. It is one of a series - one git repo per BACnet profile.
Favour clarity over cleverness; the code should read like a tutorial.

**This repository is canonical for BACnet/SC in the example series.** Both the
BACnet/SC protocol configuration and the WebSocket/TLS transport underneath it
are real and verified against real peers. Open work and known limitations are
tracked as [GitHub issues](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues),
not in a TODO file. Some limitations are by design (no host-name check on the
connector; BACnet/SC certificates identify devices, not DNS names) - check the
issues and README "Security" before "fixing" one.

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
  `--cert-label`: the built-in lab certificate generator. It writes PEM files
  named after the Network Port properties (`operational-certificate.pem`,
  `private-key.pem`, `certificate-signing-request.pem`,
  `issuer-certificate.pem`, `issuer-private-key.pem`) plus one
  `clients/<label>/` folder per connecting device, runs before the stack
  starts, and exits. The file-name constants live in `cert_tool.h`, and
  `CertTool::ResolveCertFile` is the ONE place the hub picks between them
  and the older `hub.crt`/`hub.key`/`hub.csr`/`ca.crt` names - use it rather
  than hard-coding a name. `--add-client-certs` must keep signing with the
  existing issuer, never a new one, or running hubs stop trusting the new
  clients.
- `cert_store.{h,cpp}` - the 4 certificate File objects' contents and the
  device-B side of the BACnet/SC certificate procedures (clause 19.8.3):
  File_Size/AtomicWriteFile writes are STAGED in memory, and main.cpp's
  ReinitializeDevice callback validates and commits them on ACTIVATE_CHANGES
  or WARMSTART. Never write through to disk (a hub re-dial mid-upload would
  load a half-written certificate), and never commit a set that fails
  `ValidateStaged()` - that is what stops the hub locking itself out.
- `tests/sc/` - the BACnet/SC verification scripts
  (`hub_listener_test.py`, `fake_hub_server.py`, `file_object_test.py`,
  `cert_procedure_test.py`, `rpm_test.py`) and their own README. Re-run the relevant one after any `sc_transport/` or
  BACnet/SC-related `main.cpp` change.
- `vcpkg.json` - pins the `libwebsockets`/`openssl` dependencies (see "Build"
  below).
- `README.md` - the user manual for the application: what it does, how to
  run it, certificates, HTTP endpoints, security, troubleshooting. Write it
  for someone running the hub, describe the current behaviour only (no
  "previously"/"as of vX" history - that belongs in CHANGELOG.md), and keep it
  in step with `--help` and `example.conf`.
- `TUTORIAL.md` - how to extend and review the example, including how the
  real BACnet/SC transport works and what productionizing it further needs.
  Long-form material that would bloat the README belongs here.
- `docs/PICS.md` - the Protocol Implementation Conformance Statement. Its
  objects-and-properties section is GENERATED from `docs/objects.json`; do not
  hand-edit between the `OBJECTS-PROPERTIES` markers.
- `docs/PICS.pdf` - the PICS as a PDF, built by `docs/build-pics-pdf.py`
  (needs `pip install markdown` and Chrome/Edge). Rebuild it whenever
  `docs/PICS.md` changes, in the same commit.
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

Interactive keys while running: `h` help, `m` health/metrics snapshot, `q`
quit, up/down nudge Analog Input 1. `--generate-certs` makes a lab
certificate set first. The HTTP status page is at <http://127.0.0.1:8080/>.

## Conventions

- Device is named "Chipkin Example B-SCHUB"; vendor id 389. The objects are
  Device, Analog Input 1 "Bronze", Network Ports 1 "BACnet IP" and 2 "BACnet
  SC", and File objects 1-4 (certificates). Don't add objects the profile
  doesn't need.
- **Every object has a Description** (`ObjectDescription()` in `main.cpp`,
  enabled per object with `BACnetStack_SetPropertyEnabled`) saying what the
  object is for. A new object needs one too. Keep each under ~250 characters:
  a longer string has broken ReadPropertyMultiple ALL on the Device. The
  Device's Description carries the repository URL (`PROJECT_URL`).
- **`/health` vs `/metrics`**: `/health` answers "is the hub working?"
  (`status` ok/degraded, HTTP 200/503 - monitors act on it); `/metrics`
  answers "how much is it doing?" (counters only, always 200). Keep them
  separate. `GET /` is the human status page built from both; it links to
  `PROJECT_URL` and the CAS BACnet Stack product page (`STACK_PRODUCT_URL`).
- Implement **only** the services and objects the B-SCHUB profile requires -
  but expose **every required property** of each object for Protocol_Revision
  24. No commandable outputs, and WriteProperty only for the certificate File
  objects' `File_Size` (the clause 19.8.3 certificate procedures, with
  AtomicWriteFile and ReinitializeDevice ACTIVATE_CHANGES/WARMSTART) - this
  profile does not require DS-WP-B.
- **Never destroy the last TLS lws_context.** `ScTransport` keeps a
  process-lifetime context (`EnsureTlsLifetimeContext`), because destroying
  the last context created with `LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT` tears
  down OpenSSL for the whole process (the next `lws_create_context` crashes).
  Listener restarts - the stack's own, and `ReloadCredentials()` - depend on it.
- Two Network Port objects: 1 "BACnet IP" (BACnet/IP - keep this fully
  functional, it is the example's fallback discovery path) and 2 "BACnet SC"
  (BACnet/SC, `Network_Type = secureConnect (11)`, a **local** constant in
  `main.cpp` - not added to `common/`, see below).
- DeviceCommunicationControl (DM-DCC-B): the stack runs the enable/disable state
  machine; the `DeviceCommunicationControl` callback just validates
  `g_dccPassword` (from the config file's `dcc-password` only - there is
  deliberately no command-line flag, so it never appears in process listings)
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
  knows the read is wrong.
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
   wrong password (if `dcc-password` is set in the config file) is rejected (password-failure).
5. **BACnet/SC**: confirm the SC configuration calls all return success at
   start-up and that the console prints the `CallbackSCStartListening` line
   once, then run `tests/sc/hub_listener_test.py` (listener - always
   applicable), `tests/sc/file_object_test.py` and
   `tests/sc/cert_procedure_test.py` (certificates), and, if you touched the
   connector, `tests/sc/fake_hub_server.py` (`--sc-hub-uri`). Both transport roles are real; verify against them, do
   not claim BACnet/SC behaviour works from the configuration calls
   succeeding alone.
6. If you changed the objects or their properties, regenerate `docs/PICS.md`
   (`python tools/gen-objects-properties.py BACnetProfileExample-B-SCHUB-CPP`
   from the series root) and confirm no row comes out flagged with ⚠. Then
   rebuild `docs/PICS.pdf` (`python docs/build-pics-pdf.py`).
7. **HTTP**: `curl` `/`, `/health` and `/metrics`. `/health` must return 503
   when the hub isn't listening (e.g. start with an empty `--sc-cert-dir`).

## Releasing

Bump `APP_VERSION` in `main.cpp` (and the version in README.md and
docs/PICS.md), add an entry to [CHANGELOG.md](CHANGELOG.md), then tag
`vX.Y.Z`. The GitHub Actions workflow builds and publishes the release.

## License

The example source code is dedicated to the public domain under
[CC0-1.0](LICENSE). The CAS BACnet Stack is a separate, commercially licensed
product and is not covered by that dedication. Building this example also
links two third-party dependencies via vcpkg (never vendored into this
repository): **libwebsockets** (MIT) and **OpenSSL 3** (Apache-2.0), both used
by `sc_transport/`. See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) and
[README.md "Licensing"](README.md#licensing) for the full notices. If you add
another dependency to `vcpkg.json`, add its licence to both places in the same
change.
