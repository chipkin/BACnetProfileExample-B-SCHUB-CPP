# Changelog — `common/` (the vendored shared helper)

This is the changelog of the **`common/` folder itself**, separate from the
example's own `CHANGELOG.md`. The folder is vendored (copied) into every
example repository in the BACnet profile example series; this file plus the
`COMMON_VERSION` constant in `CASExampleHelper.h` tell you whether a given
example's copy is stale.

**Rule:** any change to anything in `common/` bumps `COMMON_VERSION`, gets an
entry here, and must then be re-copied into **every** example in the series.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the folder adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2026-09-15

### Added

- `PROPERTY_IDENTIFIER_ROUTING_TABLE = 428` in `CASBACnetStackExampleConstants.h`
  (Network Port's `Routing_Table`, optional - `BACnetStack_SetPropertyEnabled`
  first). Matches `BACnetPropertyIdentifier.h`'s `routingTable = 428`. First
  consumer: `BACnetProfileExample-B-RTR-CPP` (F-ROUTER, Wave 2), which enables
  it on both its Network Port objects so a client can read back the routing
  table it configures with `AddRouterPort`/`AddRouterRoute`.

## [2.4.0] - 2026-09-15

### Added

- `KeyCommand::RouterAnnounce` (key `r` / `R`), wired in `PollKey()` on both the
  Windows (`_getch`) and POSIX (raw-terminal `read`) code paths. Non-breaking,
  purely additive: existing `switch (CASExampleHelper::PollKey())` call sites
  with a `default:` case (every current example) build unchanged.
- Claimed in the series-wide `docs/menu-keys.md`: manually (re-)send
  I-Am-Router-To-Network now, instead of waiting for the one sent at start-up,
  so routing can be demonstrated on demand. First consumer:
  `BACnetProfileExample-B-RTR-CPP`'s F-ROUTER demo (Wave 2); any later
  routing/gateway example (e.g. B-GW) reuses this same key rather than
  claiming a new one.

## [2.3.0] - 2026-09-15

### Added

- Multi-port UDP support: `SetupUDP(uint16_t port, uint32_t networkPortInstance)`
  and `SendIAm(uint32_t deviceInstance, uint32_t networkPortInstance)` overloads,
  backed by a small internal table of UDP socket bindings keyed by Network Port
  instance (`CASExampleHelper.cpp`, `UdpBinding` / `g_udpBindings`), replacing the
  single file-local `SimpleUDP g_udp`. `HelperReceiveMessage` now polls every
  bound socket in round-robin order and reports the instance a datagram actually
  arrived on; `HelperSendMessage` looks up the socket bound to the instance the
  stack names instead of comparing against one "the" instance.
- First consumer: `BACnetProfileExample-B-RTR-CPP` (Wave 2, F-ROUTER /
  F-MULTIPORT canonical example), which owns two Network Port objects ("Vermilion"
  and "Vermilion 2") on two UDP ports and needs the receive/send callbacks to
  dispatch on `networkPortInstance` per ANSI/ASHRAE 135 routing (`AddRouterPort`,
  `AddRouterRoute`, `SendIAmRouterToNetwork`).

### Non-breaking for every single-port example

- `SetupUDP(uint16_t port)` and `SendIAm(uint32_t deviceInstance)` keep their
  existing signatures and now simply forward to the two-argument overloads with
  `networkPortInstance` = whatever `SetNetworkPortInstance()` last set (instance 1
  by default, unchanged). A single-port example therefore ends up with exactly one
  entry in the internal binding table, and every codepath (receive round-robin
  over one entry, send lookup against one entry) collapses back to the same work
  the old single-`SimpleUDP` implementation did. See the "WHY THIS IS SAFE FOR
  SINGLE-PORT EXAMPLES" comment above `struct UdpBinding` in
  `CASExampleHelper.cpp`.
- Verified directly against `BACnetProfileExample-B-SS-CPP` itself (single Network
  Port, instance 1): rebuilt STATIC against the pinned stack, smoke-tested on a
  non-default port — startup, `Listening for BACnet/IP on UDP port ...`, the
  broadcast I-Am, and a Who-Is/I-Am/ReadProperty exchange with an external client
  all matched the pre-change baseline byte-for-byte in content (only the RX/TX log
  lines gained a trailing `(Network Port N)` annotation).
- The `RX`/`TX` console log lines gained a trailing `(Network Port N)` annotation;
  no gate script or CI step matches those lines verbatim (checked:
  `tools/check-series.sh`, `tools/*.sh` contain no `RX %u bytes` / `TX %u bytes`
  pattern), and the existing substring checks in the runbook's smoke-test step
  (`Listening for BACnet/IP on UDP port ...`, `... (broadcast)`) still match as
  prefixes of the new lines.

## [2.2.0] - 2026-09-15

### Added

- `KeyCommand::WriteGroupDemo` (key `w` / `W`) and `KeyCommand::DiscoverRemote`
  (key `d` / `D`), wired in `PollKey()` on both the Windows (`_getch`) and
  POSIX (raw-terminal `read`) code paths. Non-breaking, purely additive:
  existing `switch (CASExampleHelper::PollKey())` call sites with a `default:`
  case (every current example) build unchanged.
- Claimed in the series-wide `docs/menu-keys.md`: `WriteGroupDemo` manually
  fires a demo WriteGroup (or other outbound `SendWriteProperty`) instead of
  waiting for whatever normally triggers it; `DiscoverRemote` sends a demo
  `SendWhoIs` to discover a remote device this example writes to or reads
  from. First consumer: `BACnetProfileExample-B-LS-CPP`'s F-CHANNEL /
  F-EXTWRITE / F-SCHED-E demo (Wave 2); any later example with a remote-write
  or remote-discovery demo reuses these same keys rather than claiming new
  ones.

## [2.1.0] - 2026-09-15

### Added

- `KeyCommand::DemoAdvance` (key `s` / `S`), wired in `PollKey()` on both the
  Windows (`_getch`) and POSIX (raw-terminal `read`) code paths. Non-breaking,
  purely additive: existing `switch (CASExampleHelper::PollKey())` call sites
  with a `default:` case (every current example) build unchanged.
- Claimed in the series-wide `docs/menu-keys.md`: "Advance the demo Schedule to
  its next `Weekly_Schedule` time-value immediately, bypassing the wall-clock
  wait, so a Schedule-driven write can be demonstrated on demand." First
  consumer: `BACnetProfileExample-B-AAC-CPP`'s SCHED-I-B demo (Wave 1); any
  later example with a Schedule-driven demo reuses this same key rather than
  claiming a new one.

## [2.0.0] - 2026-09-09

### Changed — BREAKING, required by the CAS BACnet Stack interface update

The stack's transport and time callbacks changed shape. Every example in the
series must take this version of `common/` together with the matching `main.cpp`
edits; an old `main.cpp` will not build against this helper and vice versa.

- **A link is now identified by its Network Port object INSTANCE, not by a
  transport network type** (stack issues #822/#556). Three call sites moved:
  - `RegisterCallbackReceiveMessage` → **`RegisterCallbackReceiveMessageForPort`**;
    the callback's trailing `uint8_t* networkType` became
    `uint32_t* networkPortInstance`.
  - `RegisterCallbackSendMessage` → **`RegisterCallbackSendMessageForPort`**;
    the callback's `const uint8_t networkType` became
    `const uint32_t networkPortInstance`.
  - `BACnetStack_SendIAm()` takes the Network Port instance where it took the
    network type.
- **New: `SetNetworkPortInstance()`.** The helper has to know which Network Port
  object owns its socket. Call it after `BACnetStack_AddNetworkPortObject()` and
  before `RegisterCommonCallbacks()`. It defaults to 1 (the series convention),
  so an example using instance 1 keeps working without the call, but calling it
  keeps `main.cpp`'s Network Port instance the single source of truth.
- **`GetSystemTime` returns `CASBACnetTime` (`int64_t`), not `time_t`.** `time_t`
  is 32-bit in some toolchains and 64-bit in others; with the stack and the
  application disagreeing, every timestamp crossing the ABI was corrupted.
- **New error-code constants** in `CASBACnetStackExampleConstants.h`:
  `ERROR_CODE_READ_ACCESS_DENIED`, `ERROR_CODE_UNKNOWN_PROPERTY`,
  `ERROR_CODE_INVALID_ARRAY_INDEX` and `ERROR_CODE_SUCCESS`, for the `errorCode`
  out-parameter the `GetProperty*` callbacks gained (stack issue #974).
  `NETWORK_TYPE_IP` is retained but is no longer used by the helper.

## [1.5.1] - 2026-07-31

### Fixed

- **`--help` printed the version banner twice.** The handler printed it, then called
  `PrintHelp()` which printed it again. The interactive key list is now a separate
  internal helper, so `--help` prints banner → usage → keys once each. `PrintHelp()`
  (what the `h` key shows) is unchanged.
- **`common/README.md` was stale and taught a `main()` skeleton that no longer works.**
  It still said the stack "is compiled from source… there is no DLL to load at runtime",
  and its snippet omitted `LoadBACnetFunctions()` — which 1.5.0 made mandatory in every
  link mode. Anyone using that snippet as their starting point wrote the exact bug 1.5.0
  was written to prevent (in DLL mode, a null-pointer call). The README now leads with the
  load call and explains why it is not optional.

## [1.5.0] - 2026-07-31

### Changed

- **`CASExampleHelper.cpp` now includes `CASBACnetStackAdapter.h` instead of
  `CASBACnetStackDLL.h`.** No functional change to `common/`'s own code — it still
  calls `BACnetStack_*` directly, same as before. This is a **contract change for
  every consuming example's `main()`**: it must call `LoadBACnetFunctions()` once,
  before any `BACnetStack_*` call (including before `CASExampleHelper::PrintVersion`
  / `HandleHelpAndVersionArgs`, which call `BACnetStack_GetAPIMajorVersion()` etc.),
  in every link mode. In source/static-lib mode this was previously a no-op (the
  functions are always callable — "linked directly, there is no load step," per the
  old header comment); the adapter's DLL mode makes that no longer universally true,
  so the load step is now mandatory everywhere for one call to work in all three
  modes. Each example in the series adopts this as it re-syncs to 1.5.x, and its
  `main()` must gain the `LoadBACnetFunctions()` call at that point.

## [1.4.0] - 2026-07-18

### Added

- **`RequestRestart()` / `RestartDue()` — the deferred-restart pattern for
  `ReinitializeDevice` (DM-RD-B).** A `ReinitializeDevice` callback must not
  restart the device inside the callback: returning `true` only *encodes* the
  SimpleACK, which does not reach the wire until a later `BACnetStack_Tick()`.
  Restarting (or exiting, or resetting) before that tick means the ACK is never
  transmitted and the client reports a timeout against a device that did exactly
  what it was asked — the classic DM-RD-B interop bug. The callback now records a
  deadline and returns; the main loop restarts once the deadline passes.
  Adopted by B-AAC (the only example in the series whose profile includes
  DM-RD-B); the helper is inert in every example that never calls it. Adoption
  checklist in `docs/deferred-restart-adoption.md` (B-AAC).
  - The deadline uses a **monotonic** clock (`GetTickCount64` / `CLOCK_MONOTONIC`),
    not `time()`: a device supporting DM-TS-B can have its wall clock stepped
    backwards by a management station mid-delay, which would strand or prematurely
    fire the pending restart.
  - Repeat requests keep the **earliest** deadline (a second client cannot
    postpone a restart already promised to the first) and let Cold upgrade a
    pending Warm.

### Fixed

- **B-OD's `CASBACnetStackExampleConstants.h` was stale** — it never received the
  `NETWORK_NUMBER_QUALITY_*` constants or the
  `AddNetworkPortObjectWithNetworkNumber` comment update from the 2026-07-17
  item-16 migration, because B-OD was the one example that did not itself need the
  migrated call. That silently broke the folder's byte-identical guarantee (the
  rule this file states, and that parent-repo CI enforces) in a repo where nothing
  failed to compile. Re-synced with this release's sweep.

### Notes

- The folder is verified **content-identical in all eight examples** as of this
  release. A working-tree scan on Windows shows CRLF in six repos and LF in two,
  which looks like drift but is not: every committed blob is LF in all eight, and
  the difference is local `core.autocrlf` checkout behaviour. Compare with
  `git show HEAD:common/<file>`, or `diff --strip-trailing-cr`, when auditing this
  — a naive working-tree `diff -r` reports eight files of phantom drift.

## [1.3.0] - 2026-07-16

### Changed

- **`ParsePortArg` / `ParseDeviceIdArg` now reject non-numeric input instead of
  silently accepting it.** They used `atoi`/`atol`, which return `0` on garbage -
  so `--deviceID abc` parsed as device **0** (a valid instance) and the operator
  shipped a device answering at the wrong address with no diagnostic. Both now
  validate the whole token with `strtol` + an end-pointer check (new
  `ParseWholeNumber` helper) and print a `Warning:` naming the bad value and the
  default they fell back to. Added `#include <errno.h>`.

## [1.2.0] - 2026-07-15

The **reconciliation release**: this is the first version that is genuinely
byte-identical in every example, and the first that is enforced rather than
asserted.

### Fixed

- **`PollKey()` no longer blocks the tick loop forever when stdin is not a tty.**
  `EnableRawInput()` called `tcgetattr` first and **returned early on failure**,
  before setting `O_NONBLOCK`. Under CI, `docker run -i` without `-t`, or a pipe
  with no data, the next `read(STDIN_FILENO, ...)` blocked indefinitely —
  `BACnetStack_Tick()` never ran again and **the device went deaf while still
  looking alive**. `O_NONBLOCK` is now set unconditionally, before the tty check;
  raw mode is still only applied to a real terminal. (`< /dev/null` masked this,
  which is why it survived the smoke tests.)
- **Windows now asks for `SO_EXCLUSIVEADDRUSE` instead of `SO_REUSEADDR`.** On
  Windows `SO_REUSEADDR` lets *any* other local process bind the same port and
  silently steal traffic — the exact failure the series runbook's gotcha 2 warns
  about ("a stale instance can answer your requests and make a correct device look
  broken"), shipped enabled in the file customers copy. POSIX keeps
  `SO_REUSEADDR` (there it mainly means "rebind quickly after restart", which is
  what makes multi-device testing work). The comment now states the hazard, not
  just the convenience.

### Added

- **`HandleHelpAndVersionArgs()` — `--help` and `--version` now actually exist.**
  The series conventions require every example to parse `--help`, `--version`,
  `--deviceID` and `--port`, and every README documented all four, but the helper
  only ever parsed `--port` and `--deviceID`: `--help` was the first thing a
  newcomer typed and the app just booted. Also accepts `-h` and `/?`.
- `CASBACnetStackExampleConstants.h` is now the **true series-wide union**, not
  just B-SS's set: DeviceCommunicationControl (`DCC_*`,
  `SERVICE_DEVICE_COMMUNICATION_CONTROL`, `ERROR_CODE_PASSWORD_FAILURE`),
  alarm/event (`SERVICE_ACKNOWLEDGE_ALARM`, `*_EVENT_NOTIFICATION`,
  `SERVICE_GET_EVENT_INFORMATION`, `NOTIFY_TYPE_*`,
  `OBJECT_TYPE_NOTIFICATION_CLASS`, `OBJECT_TYPE_ANALOG_VALUE`),
  ReinitializeDevice, time-sync, RPM/WPM, the A-side `*_SERVICE_TYPE` aliases and
  `BACNET_DATATYPE_REAL`, and `ENGINEERING_UNITS_PERCENT`.

### Notes

- **The 1.1.0 entry below claimed this file was already the "series-wide
  superset". That was false**, and the claim did real damage: B-SS's copy never
  had the `DCC_*` constants that B-ASC had carried since its first commit, so the
  runbook's own instruction to seed a new example's `common/` from B-SS **would
  not compile** for any DCC-bearing profile. 1.2.0 is the first version for which
  the claim is actually true.
- Measured before this release: only **2 of 6** populated examples declared
  `COMMON_VERSION` at all (B-SS, B-SA); B-ASC, B-AAC, B-OD and B-LD had neither it
  nor this changelog — so the staleness mechanism did not lie, it **did not
  exist** in those repos, and their `PrintVersion` could not print the helper
  version line. Fixed by sweeping this folder to every example.
- Going forward this is checked, not trusted: the parent repo's CI diffs every
  `examples/*/common` against B-SS's and fails on any delta.

## [1.1.0] - 2026-07-14

### Added

- `COMMON_VERSION` constant in `CASExampleHelper.h` and this changelog — the
  folder now carries its own version so each example can tell whether its
  vendored copy is stale. `PrintVersion` prints it alongside the app + stack
  versions.
- `CASBACnetStackExampleConstants.h` gained the output object types, the
  commandable-property identifiers (`Priority_Array`, `Relinquish_Default`), and
  the error codes introduced for B-SA. (This entry originally claimed the file was
  the "series-wide superset" — see the 1.2.0 notes; it was not.)

## [1.0.1] - 2026-06-16

### Fixed

- `GetPrimaryIPv4` (Windows): check the subnet-mask `inet_pton` return and
  zero-initialize the `in_addr`, so a mask string that fails to parse can no
  longer be read uninitialized (it falls back to the limited broadcast).
  (Shipped in B-SS v1.0.2; the folder was unversioned at the time.)

## [1.0.0] - 2026-06-16

### Added

- Initial vendored helper: `CASExampleHelper` (UDP transport + time callbacks,
  version/help printing, `--port` / `--deviceID` parsing, keyboard commands
  h/q/up/down, local-IPv4 + broadcast lookup, unsolicited I-Am on start-up),
  `SimpleUDP` (cross-platform UDP socket wrapper), and
  `CASBACnetStackExampleConstants.h`.
