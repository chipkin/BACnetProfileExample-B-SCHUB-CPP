# AGENTS.md

Guidance for AI coding agents working in this repository. See
<https://agents.md/> for the format. Human contributors should read
[README.md](README.md) first, then [TUTORIAL.md](TUTORIAL.md).

## What this project is

A **tutorial** C++ example that implements the BACnet **B-SCHUB (BACnet Secure
Connect Hub)** device profile using the CAS BACnet Stack. It is one of a series -
one git repo per BACnet profile. The code should read like a tutorial a customer
can learn from and copy. Favour clarity over cleverness.

It is an **example, for evaluation and testing only**, reduced to what the
B-SCHUB profile requires. A production BACnet/SC hub is a separate Chipkin
product. Keep it that way:

- **At most 4 BACnet/SC devices** (`SC_MAX_HUB_CONNECTIONS` in `main.cpp`),
  fixed - no option or config to raise it.
- **Stops after 24 hours** (`DEMO_RUN_LIMIT_SECONDS`), fixed. Only a test may
  shorten it, with the environment variable `BSCHUB_TEST_RUN_LIMIT_SECONDS`
  (never a command-line option; it can't raise the limit).
- **BACnet/SC only** - no BACnet/IP port, no UDP socket, no `--port`. The
  device is reached through its hub function. The BACnet/SC Network Port stays
  instance 2 (the CARI tree's `port-2`).
- **The product messages appear only at start-up and on limit errors**: the
  start-up banner (`STARTUP_BANNER_FORMAT`), the connection-limit warning
  (`CONNECTION_LIMIT_MESSAGE`) and the run-limit stop (`RUN_LIMIT_MESSAGE_FORMAT`).
  All three end with `PRODUCT_CONTACT` ("... the Chipkin BACnet SC Hub: Contact
  Chipkin sales@chipkin.com"). Don't add more - not in `--help` either.
- **The log file is `logs/B-SCHUB.log`** in the working folder (`log_file.cpp`):
  every console line, emptied at each start-up. No rotation, no option, no
  other log file.
- **No production conveniences**: no HTTP server, service mode, installers,
  config file, hub connector, extra command-line options. They belong to the
  product. Keep the command line small.
- **The hub never signs certificates.** It makes only its own request at
  start-up (`hub-cari-request.zip`, never overwritten; a new key only when it
  has none - an existing key is never replaced), a new key and CSR on
  GENERATE_CSR_FILE, and installs a CA's CARI response (`--import-cari`,
  clause 19.8.3 writes). `tools/make_test_certs.py` is the test CA, for
  testing only.

## Layout

This repository is self-contained:

- `main.cpp` - the example device: objects, BACnet/SC configuration, the
  certificate procedures, the command line and the main loop.
- `common/` - the shared helper, vendored in-repo (a copy - see Conventions).
- `sc_transport/` - the BACnet/SC WebSocket+TLS transport (`ScTransport`,
  libwebsockets + OpenSSL via vcpkg) and the stack&lt;-&gt;transport glue
  (`ScTransportRouter`). Read `sc_transport/README.md` (the wire-level
  contract) before changing anything there - several of its rules come from
  reading the stack's source, not its manual.
- `cert_layout.{h,cpp}` - where every certificate file is in `--sc-cert-dir`
  (a CARI tree, ANSI/ASHRAE 135-2024 Annex AA.2). `ResolveHubCertPaths` is the
  ONE place that knows the names - use `g_certPaths` in `main.cpp`.
- `cari.{h,cpp}` - CARI zip files on zlib. The reader takes input from anyone:
  it checks sizes, entry counts, methods and every path BEFORE extracting.
  Don't loosen those checks.
- `cert_tool.{h,cpp}` - the start-up certificate request (`EnsureHubRequest`)
  and `--import-cari`.
- `log_file.{h,cpp}` - `logs/B-SCHUB.log`: stdout and stderr through a pipe,
  copied to the console and the file.
- `cert_store.{h,cpp}` - the 4 certificate File objects and the device-B side
  of the clause 19.8.3 procedures: writes are STAGED, and ReinitializeDevice
  ACTIVATE_CHANGES validates and commits them. Never write through to disk,
  and never commit a set that fails `ValidateStaged()`.
- `certs/` - the **demo certificate set** (public keys and private keys,
  including the CA's - see `certs/README.md`). Made with
  `tools/make_test_certs.py --hub-uri wss://127.0.0.1:4443/ --portable`.
- `tools/make_test_certs.py` - test certificates (testing only).
- `tests/sc/` - the verification scripts and their README. `sc_client.py` is
  the BACnet client every BACnet test uses: bacpypes3 on a hub connection.
- `README.md` - what this example is and how to run it.
- `TUTORIAL.md` - how the code works and how to extend and review it.
- `docs/PICS.md` - the Protocol Implementation Conformance Statement. Its
  objects-and-properties section is GENERATED from `docs/objects.json`; do not
  hand-edit between the `OBJECTS-PROPERTIES` markers. README.md carries the same
  generated block; regenerate both together.
- `docs/objects.json` - the input to that generator. Update it in the same change
  as any `main.cpp` change that adds an object or a `GetProperty*` branch.
- `docs/code-signing.md` - what the release workflow needs for signing.
- `THIRD-PARTY-NOTICES.md` - licence notices for the vcpkg libraries.
- `vcpkg.json` - pins `libwebsockets`, `openssl` and `zlib`.
- `submodules/cas-bacnet-stack/` - the **CAS BACnet Stack** as a git submodule
  (private; compiled from source). After cloning, run
  `git submodule update --init --recursive`.

The `PROFILE-TABLE` block in README.md is also generated, from the example-series
repository's `docs/profile-table.md`. Edit it there, not here.

## Build

Plain CMake, in the adapter's default SOURCE mode (the stack's sources are
compiled into the executable):

```bash
git submodule update --init --recursive   # once, if not cloned with --recursive
cmake -B build -S .
cmake --build build --config Release
```

**This repository needs `VCPKG_ROOT` set** (vcpkg manifest mode, `vcpkg.json`):
the transport depends on libwebsockets, OpenSSL and zlib. A Visual Studio
Developer Command Prompt already has it. The first build compiles the stack
(~600 files) and, once per machine, OpenSSL (10-15 minutes); later builds are
incremental. Use `-D CAS_STACK_DIR=...` only if your stack lives outside the
bundled submodule.

## Run

```bash
./build/BACnetExampleBSCHUB [--sc-port 4443] [--sc-cert-dir certs]   # Linux/macOS
.\build\Release\BACnetExampleBSCHUB.exe [--sc-port 4443]            # Windows
```

It runs from the repository folder with the demo certificates in `./certs`,
and writes `logs/B-SCHUB.log` there (and `certs/hub-cari-request.zip` - both
git-ignored).
Device instance 389022 (fixed - the series' table entry for B-SCHUB).
Interactive keys while running: `h` help, `q` quit, up/down nudge Analog
Input 1, `m` BACnet/SC counters.

## Conventions

- Device "Chipkin Example B-SCHUB", Model_Name "CAS BACnet Stack Example -
  B-SCHUB", vendor id 389. Analog Input 1 "Bronze" (series colour); Network
  Ports and File objects are purpose-named. Don't add objects the profile
  doesn't need.
- Implement **only** the services and objects the B-SCHUB profile requires -
  but expose **every required property** of each object for Protocol_Revision
  30. Every object has a Description (`ObjectDescription()`); keep each under
  ~250 characters.
- BACnet/SC setup order: `BACnetStack_SetBACnetSCUuid` (once), then
  `BACnetStack_AddBACnetSCAcceptUri`, then
  `BACnetStack_SetBACnetSCHubFunctionConfig`. The transport callbacks are thin
  forwards to `ScTransport` - never replace them with a fake success path.
- Every `GetProperty*` callback ends with `uint32_t* errorCode`. Leave it alone
  on a catch-all decline; set it only where the device knows the read is wrong.
- Never destroy the last TLS `lws_context` (`EnsureTlsLifetimeContext`).
- Match the surrounding code style: `const`-correct parameters, check every stack
  return value, keep `main.cpp` linear and well-commented. No compiler warnings.
- **Never edit `common/` in this repo alone** - it is a vendored copy shared by
  every example in the series, with its own version (`COMMON_VERSION`) and
  changelog (`common/CHANGELOG.md`). To change it: edit, bump the version, add
  a changelog entry, then re-copy `common/` into every example repository.

## How to verify a change

There are no unit tests; verification is behavioural (`tests/sc/README.md` has
every command):

1. Build, then run the example with the demo certificates on clear ports.
2. Over BACnet/SC (there is no BACnet/IP): `rpm_test.py` (Who-Is/I-Am from
   389022 through the hub, ReadPropertyMultiple, `Protocol_Revision` 30, one
   Network Port - 2 - in `Object_List`), `segmentation_test.py`.
3. BACnet/SC: `hub_listener_test.py`, `file_object_test.py`,
   `cert_procedure_test.py`, `connection_limit_test.py`. Don't claim BACnet/SC
   works from the configuration calls succeeding alone.
4. Certificates: `hub_cert_test.py`, `cert_files_test.py`.
5. Start-up and limits: `startup_test.py` (`--help`, the log file, no
   BACnet/IP), `run_limit_test.py`.
6. If you changed the objects or their properties, regenerate `docs/PICS.md`
   (`python tools/gen-objects-properties.py BACnetProfileExample-B-SCHUB-CPP`
   from the series root), copy the block into README.md, and confirm no row is
   flagged with ⚠.

## Releasing

Bump `APP_VERSION` in `main.cpp`, `version-string` in `vcpkg.json`, the README
"Versions" note and sample output, and the PICS (title and Application
Software Version), add an entry to [CHANGELOG.md](CHANGELOG.md), then tag
`vX.Y.Z`. The GitHub Actions
workflow builds, tests, signs (Windows) and publishes the release with
`SHA256SUMS.txt`; see [docs/code-signing.md](docs/code-signing.md).

## License

See [LICENSE](LICENSE) (CC0-1.0). The CAS BACnet Stack is a separate,
commercially licensed product and is not covered by it. libwebsockets, OpenSSL
and zlib keep their own licences - see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
