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

## [3.0.0] - 2026-09-22

### Added

- **Reconciled two `common/` lines that had independently diverged from
  2.5.0 and both reused version numbers for different content**:
  `BACnetProfileExample-B-BC-CPP` had carried its own 2.6.0-2.9.0 (RX/TX
  service decode, object/property-naming `SummarizeBacnetFrame()`, the
  `--xml` frame dump, `GetLocalLinkSpeedBitsPerSecond()`, and the Device
  `Local_Date`/`Local_Time` property IDs) without those changes being
  re-copied series-wide, while `BACnetProfileExample-B-SCHUB-CPP` separately
  carried its own, differently-numbered 2.6.0-2.7.0 (the `CASExampleLog`
  structured-logging facility, `ParseDccPasswordArg()`, the
  `HandleHelpAndVersionArgs()` `showDccPasswordCliOption` parameter, and
  `KeyCommand::Metrics`). The two lines touch disjoint code (confirmed by
  diffing each against the shared 2.5.0 ancestor) and merge cleanly with no
  functional conflicts. This version combines both: every symbol and file
  from both lines is present, `COMMON_VERSION` moves to `3.0.0` (a new major
  number precisely because this single version now carries two
  independently-versioned change sets, not because anything is
  backward-incompatible), and this is the version every example in the
  series is re-synced to.

## [2.7.0] - 2026-09-21 (from the BACnetProfileExample-B-SCHUB-CPP line, merged in 3.0.0)

### Added

- **`KeyCommand::Metrics` ('m'/'M')** - a generic "print a health/metrics
  snapshot" interactive key command, added for
  `BACnetProfileExample-B-SCHUB-CPP`'s health/metrics keypress (this batch's
  Task 2: uptime, connection counts, rate-limit rejections, RX/TX counters).
  `'h'`/`'q'`/arrows/`'s'`/`'w'`/`'d'`/`'r'` were already taken (see
  `KeyCommand`'s own comment), so this is a new enum value, not a repurposed
  one. `PollKey()` (both the Windows `_kbhit`/`_getch` branch and the POSIX
  raw-input branch) now recognises `'m'`/`'M'` and returns it. This is a
  purely additive, backward-compatible enum/switch change - existing
  `switch (PollKey())` call sites elsewhere in the series that do not handle
  `Metrics` are unaffected (an unhandled `default:`/no `case` simply does
  nothing, same as any other key this repo's own `main.cpp` chooses not to
  act on). Kept generic (not BACnet/SC-specific) so any other example that
  later tracks its own connection/throughput counters can reuse the same key
  rather than main.cpp inventing a parallel one.

### Changed

- **`HandleHelpAndVersionArgs()` gains an optional 5th parameter,
  `showDccPasswordCliOption` (default `true`).** Added so
  `BACnetProfileExample-B-SCHUB-CPP` can stop advertising `--dcc-password` in
  its own `--help` output (this batch's Task 1: the CLI form of
  `--dcc-password` was removed from that repo - config-file only now, since a
  CLI argument is visible in process listings/shell history) without
  affecting any other example's `--help` output. This is a **non-breaking**
  change: every existing 4-argument call site (`HandleHelpAndVersionArgs(argc,
  argv, APP_NAME, APP_VERSION)`) keeps compiling and keeps printing the
  `--dcc-password` line exactly as before, because the new parameter defaults
  to `true`. `ParseDccPasswordArg()` itself is UNCHANGED and NOT removed -
  see that function's own entry in the 2.6.0 section below; any example
  (including this one, previously) can still call it directly for a CLI
  `--dcc-password` flag if it wants one. Evaluated and rejected: removing
  `ParseDccPasswordArg()` outright, since (a) it was only added in 2.6.0 (this
  same day) with no evidence any other example in the series has adopted it
  yet, but (b) removing a just-published shared function the moment after
  publishing it, rather than simply not using it in this one repo, is more
  invasive than the problem calls for - see
  `BACnetProfileExample-B-SCHUB-CPP`'s own `CHANGELOG.md` for the full
  reasoning.

## [2.6.0] - 2026-09-21 (from the BACnetProfileExample-B-SCHUB-CPP line, merged in 3.0.0)

### Added

- **`CASExampleLog.h` / `CASExampleLog.cpp` - a minimal, dependency-free
  structured logging facility.** Every example in the series (this repo
  included) has always logged via bare `printf()`/`fprintf(stderr, ...)`
  calls scattered through `main.cpp` and its own transport code - no levels,
  no timestamps, no way to turn the noise up or down. `CASExampleHelper::Log()`
  is a drop-in replacement for that pattern, not a new subsystem: no external
  logging library (just `<cstdio>`/`<cstdarg>`/`<ctime>`, already pulled in
  elsewhere in `common/`), no file output or rotation (explicitly out of
  scope for this pass), still stdout/stderr underneath. `LogLevel` -
  `Debug`/`Info`/`Warning`/`Error` - matches the naming already used for
  `CASExampleHelper::RestartKind`/`KeyCommand` in this same namespace.
  `SetLogLevel()`/`GetLogLevel()` give a runtime-configurable minimum
  (default `Info`, so `Debug` stays silent unless an example opts in) - this
  is what the rate-limiting/audit-trail work planned for
  `BACnetProfileExample-B-SCHUB-CPP` will use for verbose diagnostics without
  spamming normal operation. `Log(level, fmt, ...)` is printf-style
  (`const char* fmt, ...`) specifically to keep call-site conversions small:
  an existing `printf("Warning: ...", x)` becomes
  `CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning, "...", x)` and
  nothing else changes. Each line is `<UTC timestamp> [<LEVEL>] <message>`;
  the timestamp uses the same `gmtime_s`/`gmtime_r` pattern
  `BACnetProfileExample-B-SCHUB-CPP`'s own `main.cpp` already uses for its
  File objects' `Modification_Date` (UTC, not `localtime()`, so a line means
  the same instant regardless of the host's configured timezone). `Debug`/
  `Info` go to stdout, `Warning`/`Error` go to stderr, matching the split
  `sc_transport/ScTransport.cpp`/`ScTransportRouter.cpp` already use for their
  own `printf` (FYI/status) vs `fprintf(stderr, ...)` (problem) calls.
  First consumer: `BACnetProfileExample-B-SCHUB-CPP`, which converts 3
  `main.cpp` call sites (the DeviceCommunicationControl password-failure
  rejection, the "could not read a local IPv4 address" fallback, and the
  BACnet/SC hub accept-URI failure) as a proof it compiles and works. This is
  deliberately NOT a sweep of every `printf`/`fprintf` call in that repo -
  that is a large, separate, mechanical change with real regression risk
  (its RX/TX log line format, startup banner, etc. are read, though not
  matched verbatim, by `tests/sc/*.py`) - left for a later, dedicated pass.
  Any other example in the series can adopt the facility the same way, at its
  own pace: a `#include "CASExampleLog.h"` and converting call sites as it
  goes.
- **`ParseDccPasswordArg()` - `--dcc-password <string>` as a shared CLI
  argument.** Every example that implements DM-DCC-B has, until now, hardcoded
  its DeviceCommunicationControl password at compile time (e.g.
  `BACnetProfileExample-B-SCHUB-CPP`'s `main.cpp` had
  `static const char* DCC_PASSWORD = "";`) - there was no way to set or test a
  non-empty password without rebuilding. `ParseDccPasswordArg(argc, argv,
  defaultPassword)` follows the exact same shape as `ParsePortArg`/
  `ParseDeviceIdArg`: scan `argv` for the flag, return the following token if
  present, else `defaultPassword`. It differs from those two only in return
  type - `const char*` into `argv`'s own storage, not a parsed numeric value -
  because a password is carried through verbatim, not converted; `argv`
  outlives `main()`, so returning a pointer into it is safe, and the contract
  matches an example's own (now non-`static const`) `DCC_PASSWORD`-equivalent
  global. Default `""` (no password required) preserves today's behaviour for
  every example that does not opt in - nothing that does not call this
  function changes. Added to `HandleHelpAndVersionArgs()`'s `--help` output,
  in the same option-list style as `--port`/`--deviceID`, so it is
  discoverable series-wide once adopted. First consumer:
  `BACnetProfileExample-B-SCHUB-CPP`, which parses it alongside `--port`/
  `--deviceID` in `main()` and renamed its own constant to `g_dccPassword`
  (no longer `static const`, since it is now assigned at start-up) feeding the
  existing `DeviceCommunicationControl` callback's password check - unchanged
  otherwise.

## [2.9.0] - 2026-09-17 (from the BACnetProfileExample-B-BC-CPP line, merged in 3.0.0)

### Added

- `CASExampleHelper::GetLocalLinkSpeedBitsPerSecond()` - reads the primary
  network interface's actual negotiated link speed (Windows: `GetIfEntry()`;
  POSIX: `/sys/class/net/<iface>/speed`), for a Network Port object's
  `Link_Speed` property. First consumer: `BACnetProfileExample-B-BC-CPP`,
  whose `Link_Speed` previously read back a hardcoded `0.0` because nothing
  served it - the stack's "no callback answered" REAL-property fallback,
  not a real "indeterminable" answer. `PROPERTY_IDENTIFIER_LINK_SPEED = 420`
  added to `CASBACnetStackExampleConstants.h` alongside it.

## [2.8.0] - 2026-09-17 (from the BACnetProfileExample-B-BC-CPP line, merged in 3.0.0)

### Added

- `PROPERTY_IDENTIFIER_LOCAL_DATE = 56` and `PROPERTY_IDENTIFIER_LOCAL_TIME = 57`
  in `CASBACnetStackExampleConstants.h`. First consumer:
  `BACnetProfileExample-B-BC-CPP` (chipkin/BACnetProfileExample-B-BC-CPP#7) -
  a device claiming DM-TS-B/DM-UTC-B needs to actually serve the Device's
  `Local_Date`/`Local_Time` (the properties a client reads back to confirm a
  time sync took), not leave the stack's "callback declined, no default"
  `read-access-denied` fallback in place.

## [2.7.0] - 2026-09-17 (from the BACnetProfileExample-B-BC-CPP line, merged in 3.0.0)

### Added

- **RX/TX log lines now name the object/property being requested, and any
  NPDU routing destination**, e.g.:
  `RX 17 bytes from ... (Network Port 1) - ConfirmedRequest: ReadProperty Device 389001.Device_Address_Binding`
  `RX 18 bytes from ... (Network Port 1) - ConfirmedRequest: ReadProperty Analog_Input 1.Present_Value DNET=1234 DADR=0A0B0C`
  `SummarizeBacnetFrame()` decodes the shared ObjectIdentifier(tag0) +
  PropertyIdentifier(tag1) + optional PropertyArrayIndex(tag2) layout common
  to ReadProperty-Request, ReadProperty-ACK and WriteProperty-Request, using
  two new lookup tables (`ObjectTypeName()`, `PropertyName()` - 65 object
  types, 522 properties, generated from the pinned stack's own
  `BACnetObjectType.h`/`BACnetPropertyIdentifier.h`, so the names are exactly
  what this stack build uses, not hand-transcribed from the spec). Falls back
  to `object-type=<N> <instance>.property=<N>` for anything outside the
  tables. A trailing ` DNET=<n>[ DADR=<hex>]` is appended whenever the NPDU
  carries a destination specifier, regardless of PDU type.
  Other confirmed services (ReadPropertyMultiple, WritePropertyMultiple, ...)
  are intentionally NOT decoded this deeply - their nested
  read-access-specification/property-reference structure reuses the same
  tag numbers at a different nesting level, which this generic tag-walker
  doesn't disambiguate. Those still print with just the service name, same
  as before.
- **New `--xml` / `--xmlLog` command-line option (off by default).** When
  set, every RX/TX frame prints as a full indented XML block (BVLC function,
  NPDU version/control/routing, APDU type/invoke-id/service/object/property,
  and always the complete raw hex of the frame as a fallback) instead of the
  one-line summary - for deep protocol debugging sessions where the one-line
  summary isn't enough. `CASExampleHelper::ParseXmlLogArg(argc, argv)` is the
  only thing an example's `main()` needs to call (same pattern as
  `ParsePortArg`/`ParseDeviceIdArg`); everything else - the flag itself, the
  decode, the XML rendering - lives entirely in `common/`, invisible to
  `main.cpp`.
- New shared internals backing both of the above: a generic BACnet tag-header
  decoder (`DecodeTagHeader`, handles extended tag numbers and all four
  length/value/type encodings including the 1/2/4-byte extended-length
  escapes) and one `DecodeBacnetFrame()` parse pass that both
  `SummarizeBacnetFrame()` and the new XML dump build their output from - the
  two views can never disagree about what a frame contains, because they're
  reading the same `DecodedFrame` struct.
- Both the object/property table generation and the on-disk lookup tables are
  regenerable if the stack pin changes: `python3 -c "..."` extracts every
  `name = value,` line from `BACnetObjectType.h`/`BACnetPropertyIdentifier.h`,
  converts camelCase to `Title_Case`, sorts by value, and emits `{ id, "name" },`
  rows - see this entry's originating commit for the exact script.

## [2.6.0] - 2026-09-17 (from the BACnetProfileExample-B-BC-CPP line, merged in 3.0.0)

### Added

- **RX/TX log lines now decode and print the BACnet service**, e.g.
  `RX 21 bytes from ... (Network Port 1) - Unconfirmed: I-Am` or
  `RX 17 bytes from ... (Network Port 1) - ConfirmedRequest: ReadProperty`,
  instead of stopping at the byte count and Network Port. New
  `CASExampleHelper::SummarizeBacnetFrame()` walks the raw BVLC + NPDU + APDU
  bytes handed to the transport callbacks (the exact wire bytes - the stack
  decodes them again itself; this is a read-only, best-effort peek purely for
  the console log) far enough to name the PDU type (ConfirmedRequest /
  Unconfirmed / SimpleACK / ComplexACK / SegmentACK / Error / Reject / Abort /
  a network-layer message) and, where applicable, the Clause 21
  confirmed/unconfirmed service choice or reject/abort reason - falling back
  to `service=<N>` / `reason=<N>` (matching the stack's own log wording) for
  anything outside the lookup tables, and to `?` for a truncated/malformed
  frame rather than misreading it. Handles the DNET/SNET/hop-count routing
  fields in the NPDU so this doesn't mis-decode a routed frame.
  First landed in `BACnetProfileExample-B-SS-CPP`; every sibling example
  re-syncs to this `common/` version to pick it up.

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
