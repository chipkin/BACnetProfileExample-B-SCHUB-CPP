# BACnet B-SCHUB (BACnet/SC Hub) - C++ example

A minimal, copy-paste-friendly example showing how to implement the BACnet
**B-SCHUB (BACnet Secure Connect Hub)** device profile with the
[CAS BACnet Stack](https://store.chipkin.com/services/stacks/bacnet-stack).
It listens on **BACnet/IP (UDP 47808)**, answers **ReadProperty**, responds to
**DeviceCommunicationControl**, is discoverable via **Who-Is / I-Am**, and
configures a **BACnet/SC hub function** Network Port — see
[BACnet/SC support](#bacnetsc-support-read-this-first) below for exactly what
that last part does and does not do in this build.

Part of the CAS BACnet Stack **BACnet profile example series** - one repository
per BACnet device profile. This example claims **only** B-SCHUB.

Reading order: this repository stands on its own — **you can start here.** If you also want the
gentler introductions to the shared sensor objects and DeviceCommunicationControl,
[B-SS (Smart Sensor)](https://github.com/chipkin/BACnetProfileExample-B-SS-CPP) is the first
example in the series and [B-ASC (Application Specific Controller)](https://github.com/chipkin/BACnetProfileExample-B-ASC-CPP)
(this example's seed) demonstrates DM-DCC-B on its own; this repository repeats everything it needs.

> **Versions:** this document describes **example v1.0.0**, built and verified
> against **CAS BACnet Stack 6.0.21** (`6.x` @ `abd4cee1`), linked as a static
> library, at **Protocol_Revision 24**, with the vendored `common/` helper at
> **v2.5.0**. Running the example prints all three - if what it prints
> disagrees with this line, trust the program and check `CHANGELOG.md`.

## BACnet/SC support: read this first

This example is the series' **spike for BACnet/SC** (canonical for **F-SC**). The
short version: **the BACnet/SC protocol side is real and stack-verified; the
WebSocket/TLS transport underneath it is a documented stub, not implemented.**

**The finding (read from the stack's doc comments and
`submodules/cas-bacnet-stack/docs/CAS BACnet Stack - BACnet SC Manual_v6.md`,
not assumed):** the CAS BACnet Stack owns the BACnet/SC *protocol* - the Hello
handshake, the hub/node/direct-connect connection state machines, BVLC framing,
certificate-object bookkeeping, and every SC-related Network Port property. It
does **not** own the transport. Verbatim, from the doc comment on
`BACnetStack_RegisterCallbackInitiateWebsocket` in `CASBACnetStackDLL.h`:

> "The stack implements no WebSocket or TLS itself."

The stack asks the **host application** to actually open, accept, and close raw
WebSocket(+TLS) connections through four callbacks
(`RegisterCallbackInitiateWebsocket`, `RegisterCallbackDisconnectWebsocket`,
`RegisterCallbackSCStartListening`, `RegisterCallbackSCStopListening`) and
expects real connection status reported back through
`BACnetStack_SetBACnetSCWebSocketStatus`; certificate validation and CSR
generation are likewise host callbacks. **So: the application must supply the
WebSocket/TLS transport, not the stack.**

**What this example implements (real, compiled, stack-verified):**

- `BACnetStack_SetBACnetSCUuid` - the required device-wide SC UUID.
- A second Network Port object (2, "Vermilion 2", `Network_Type = secureConnect
  (11)`) representing the BACnet/SC data link.
- `BACnetStack_AddBACnetSCAcceptUri` + `BACnetStack_SetBACnetSCHubFunctionConfig`
  - configures and **enables** the NM-SCH-B hub function with a `wss://` accept
  URI and a connection limit.
- All five SC transport/status callbacks registered
  (`CallbackInitiateWebsocket`, `CallbackDisconnectWebsocket`,
  `CallbackSCStartListening`, `CallbackSCStopListening`,
  `CallbackBACnetSCStateChange`), so the stack's state machine runs and can be
  observed. Running the example proves this: at start-up the stack calls
  `CallbackSCStartListening` with the configured accept URI, exactly as its
  doc comment says a hub-function-enabled port must.

**What this example does NOT implement:** the WebSocket/TLS transport itself.
`CallbackInitiateWebsocket`, `CallbackSCStartListening` and their disconnect
counterparts (`main.cpp`, section **2c**) are honest **stubs** - they log
exactly what the stack asked for and return `false` / do nothing, rather than
claiming a connection that does not exist. The hub function is therefore
**configured but never actually accepts a BACnet/SC node connection** in this
build. See [`TODO.md`](TODO.md) for exactly what a real implementation needs
to add.

**Why not just write one?** Per the task's own constraint, a `common/`
WebSocket helper is acceptable only if it is small and **dependency-free** (no
vendored OpenSSL/mbedTLS/etc.), and vendoring a heavyweight TLS/crypto
dependency was explicitly out of bounds for this spike without stopping to
report it first. BACnet/SC's accept URIs are **required to use the `wss://`
scheme** (`BACnetStack_AddBACnetSCAcceptUri`'s own doc comment: *"Must use the
wss scheme"*) - i.e. TLS is not optional for a conformant SC hub, it is part of
the profile. A minimal dependency-free **WebSocket** client/listener (RFC 6455
framing over a plain TCP socket) is realistic; a minimal dependency-free
**TLS 1.2/1.3** implementation is not - every lightweight option either
vendors a crypto library or is itself a substantial, security-sensitive
project unsuitable for a tutorial example. So this example documents "bring
your own WebSocket/TLS" instead of shipping a partial, non-conformant (no-TLS)
transport that would look more finished than it safely is.

**The BACnet/IP Network Port (1, "Vermilion") stays fully active** throughout,
so this example remains discoverable and testable over plain BACnet/IP
regardless of the BACnet/SC transport gap - see [Verify](#verify) below.

## Quickstart

You need a CAS BACnet Stack licence and access to its private submodule (see
[Requires the CAS BACnet Stack](#requires-the-cas-bacnet-stack-licensed-product)).
Then:

```bash
git clone --recursive https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP.git
cd BACnetProfileExample-B-SCHUB-CPP
tools/build-stack-static.sh BACnetProfileExample-B-SCHUB-CPP    # from the series root; builds the static library
cmake -B build -S . -DCAS_BACNET_STACK_LINK=STATIC
cmake --build build --config Release
./build/Release/BACnetExampleBSCHUB.exe        # Windows; drop Release/ on Linux
```

The device announces itself over BACnet/IP, answers Who-Is, prints a line
about the (stubbed) BACnet/SC hub function, and prints `Press 'h' for help'`.

## What is a B-SCHUB (BACnet/SC Hub) profile?

A **device profile** is a standard "template" defined in Annex L of ANSI/ASHRAE
135. It lists the capabilities a class of device must support so that any
compliant client knows what to expect, and the BACnet Testing Laboratories (BTL)
certify devices against it. (New to BACnet in general? See Chipkin's
[What is BACnet?](https://docs.chipkin.com/protocols/bacnet/) guide.)

**B-SCHUB (BACnet Secure Connect Hub)** is a device that operates a
**BACnet/SC hub function**: it accepts WebSocket/TLS connections from BACnet/SC
**nodes** and relays BACnet traffic between them, the SC equivalent of a
BACnet/IP broadcast domain. BACnet/SC (Secure Connect) is the TLS/WebSocket-based
BACnet transport added in ASHRAE 135-2020 Annex AB, designed to run over
ordinary IT infrastructure (corporate networks, VPNs, the Internet) with
standard transport-layer security, unlike BACnet/IP's plain UDP.

**Reading the capability names.** Each capability below is a **BIBB** (BACnet
Interoperability Building Block) - the standard's unit of "this device can do this one
thing." Every BIBB name ends in **-A** or **-B**:

- **-A** = the **A side**, the device that *initiates* the request (a client - an operator
  workstation, a supervisory controller).
- **-B** = the **B side**, the device that *responds* to it (a server - this example).

So `DS-RP-B` reads as "Data Sharing, ReadProperty, B side": *answers* ReadProperty requests.
A device profile is essentially a required list of BIBBs.

**What the profile requires:**

- **Data Sharing - ReadProperty - B side (DS-RP-B):** answer **ReadProperty**.
- **Device Management - Dynamic Device Binding - B side (DM-DDB-B):** answer
  **Who-Is** with **I-Am**, and announce itself with an unsolicited I-Am at
  start-up, so a client can discover the device.
- **Device Management - Dynamic Object Binding - B side (DM-DOB-B):** answer
  **Who-Has** with **I-Have**, so a client can locate an object by name or ID.
- **Device Management - DeviceCommunicationControl - B side (DM-DCC-B):** respond
  to **DeviceCommunicationControl** - a management station can tell the device to
  stop or resume communicating (optionally for a time period, optionally behind a
  password).
- **Network - Secure Connect Hub Function - B side (NM-SCH-B):** operate a
  BACnet/SC **hub function** - accept SC node connections and relay traffic
  between them. See [BACnet/SC support](#bacnetsc-support-read-this-first)
  above for what that means in this build.

**What the profile does NOT require** - and this example therefore omits on
purpose: **WriteProperty**, **alarming / event reporting**, **scheduling**, and
**trending**.

**But it is still a full BACnet device.** Even a simple profile must present the
standard object model - a **Device** object, at least one **Network Port**
object (every device needs one; this device has two - see below), and its
objects - and each object must expose all of its **required properties**. The
CAS BACnet Stack generates most of those automatically (Object_Identifier,
Object_Type, Status_Flags, Object_List, Protocol_*, ...); this example supplies
the handful that are application-specific. The result is conformant for
**Protocol_Revision 24** on the BACnet/IP side; see above for the BACnet/SC
transport gap.

## DeviceCommunicationControl

`DeviceCommunicationControl` lets a management station tell a device to go quiet -
useful to silence a misbehaving or noisy device during commissioning - and later
to resume. The CAS BACnet Stack runs the actual enable/disable state machine and
the re-enable timer; this example's callback (`DeviceCommunicationControl` in
`main.cpp`) validates an optional password and logs what was asked. This is the
same pattern [B-ASC](https://github.com/chipkin/BACnetProfileExample-B-ASC-CPP)
defines for the series (this example's seed) - see that repository's README for
the full walkthrough of the password comparison and the `Protocol_Revision >= 20`
deprecation of the plain `disable` value.

The example ships with **no password** (`DCC_PASSWORD = ""`, accept any request).

## The device this example creates

```
Device 389022  "Rainbow"   (Vendor 389 - Chipkin Automation Systems)
    │
    ├── Analog Input  1       "Bronze"        Present_Value  21.5    (REAL, degrees Celsius; read-only)
    ├── Binary Input  1       "Emerald"       Present_Value  inactive  (0 = inactive / 1 = active; read-only)
    ├── Multi-State Input 1   "Hot Pink"      Present_Value  1       (state, 1..3; read-only)
    ├── Network Port 1        "Vermilion"     BACnet/IP - active, discoverable (required on every device)
    └── Network Port 2        "Vermilion 2"   BACnet/SC hub function - CONFIGURED, transport is a stub
```

The three **input** objects (Bronze, Emerald, Hot Pink) are the shared minimum
every example in this series carries. Object names follow this series'
colour-naming convention (Device is always "Rainbow"; a second instance of a
Network Port is "<Colour> 2", not a new colour).

## What this example supports

The example implements exactly the capabilities below - and nothing more, which
is the point of a profile example. These capabilities satisfy the **B-SCHUB
(BACnet Secure Connect Hub)** profile; because B-SCHUB's BIBBs are a superset of
the **B-GENERAL** baseline, a conformant B-SCHUB device necessarily satisfies
**B-GENERAL** too. That is subsumption, not a second claim: this repository
still claims exactly one profile.

### BIBBs (BACnet Interoperability Building Blocks)

| BIBB | Description | Supported |
|------|-------------|:---------:|
| DS-RP-B | Data Sharing - ReadProperty - B | ✅ |
| DM-DDB-B | Device Management - Dynamic Device Binding - B | ✅ |
| DM-DOB-B | Device Management - Dynamic Object Binding - B | ✅ |
| DM-DCC-B | Device Management - DeviceCommunicationControl - B | ✅ |
| NM-SCH-B | Network - Secure Connect Hub Function - B | 🚧 configured, transport not implemented (see above) |

### Services (executed / B-side)

| Service | Notes |
|---------|-------|
| ReadProperty | Responds to property reads (DS-RP-B). |
| Who-Is / I-Am | Answers Who-Is with I-Am, and broadcasts an I-Am on start-up (DM-DDB-B). |
| Who-Has / I-Have | Answers Who-Has with I-Have (DM-DOB-B). |
| DeviceCommunicationControl | Stops/resumes communication, optionally timed/passworded (DM-DCC-B). |
| BACnet/SC hub function | Protocol/state-machine configured and enabled (NM-SCH-B); WebSocket/TLS transport stubbed - see above. |

### Object types

| Object type | Instance | Name | Access |
|-------------|:--------:|------|--------|
| Device | 389022 | Rainbow | - |
| Analog Input | 1 | Bronze | read-only |
| Binary Input | 1 | Emerald | read-only |
| Multi-State Input | 1 | Hot Pink | read-only |
| Network Port | 1 | Vermilion | - (BACnet/IP) |
| Network Port | 2 | Vermilion 2 | - (BACnet/SC) |

## Before you ship

This example is a tutorial, and it identifies itself as one. Everything in this
table is read by clients and shown to the operator in **every discovery tool on
the network**. Left as-is, your product appears on a real site announcing itself
as a Chipkin demo. None of it is cosmetic.

| Constant (`main.cpp`) | Ships as | Change it to |
|---|---|---|
| `VENDOR_IDENTIFIER` | `389` (Chipkin) | **Your** company's vendor ID. Assigned by ASHRAE, free: <https://bacnet.org/assigned-vendor-ids/> |
| `VENDOR_NAME` | `Chipkin Automation Systems` | Your company name — must match the vendor ID above. |
| `DEVICE_NAME` | `"Rainbow"` | Your device's `Object_Name`. **Must be unique across the BACnet internetwork.** |
| `MODEL_NAME` | `CAS BACnet Stack Example - B-SCHUB` | Your model designation. |
| `DEVICE_DESCRIPTION` | a description of *this example* | What your device actually is. |
| `FIRMWARE_REVISION` / `APPLICATION_SOFTWARE_VERSION` | `1.0.0` | Your real versions — wire them to your build. |
| `DCC_PASSWORD` | `""` (no password) | Set your device's secret, or leave empty to accept any DeviceCommunicationControl. It crosses the wire in **plaintext** — a guard against accidents, not a security boundary. |
| `SC_DEVICE_UUID` | a fixed demo value | Generate/persist a stable, per-unit random UUID (RFC 4122 v4). Two devices sharing a UUID is a protocol violation. |
| Device instance | `389022` (`--deviceID` overrides) | Must be unique on the internetwork. |

`main.cpp` marks this block with a `CHANGE ALL OF THIS BEFORE YOU SHIP` banner.

## Requires the CAS BACnet Stack (licensed product)

This example **builds against the CAS BACnet Stack, which is a commercial Chipkin
product** - it is not free or open source, and there is no public/trial build.
The stack is referenced here as the **private** git submodule
`submodules/cas-bacnet-stack`; you can only fetch and build it once you have a CAS
BACnet Stack license and access to that repository.

**To get the CAS BACnet Stack (and access to build this example), contact
Chipkin:** <https://store.chipkin.com/services/stacks/bacnet-stack> or
sales@chipkin.com.

You do not need a stack licence to *read* this example. Every file outside
submodules/ is CC0 public domain.

## What's in this repository

This is a **self-contained** project. It ships:

- `main.cpp` - the example device.
- `common/` - the shared helper (UDP, callbacks, CLI, keyboard) vendored in.
- `submodules/cas-bacnet-stack/` - the **CAS BACnet Stack as a git submodule**
  (private; requires a license - see above). Built into a prebuilt **STATIC**
  library by the stack's own project files (`tools/build-stack-static.sh`),
  then linked - no DLL is shipped.

## Prerequisites

- A C++17 compiler (MSVC, GCC, or Clang).
- CMake >= 3.15.
- Git (to fetch the stack submodule).

### Windows

- **C++ compiler** - install
  [Visual Studio Community](https://visualstudio.microsoft.com/downloads/)
  (free) and select the **"Desktop development with C++"** workload.
- **CMake** - from <https://cmake.org/download/>, or `winget install Kitware.CMake`.

### Linux / macOS

- Debian/Ubuntu: `sudo apt install build-essential cmake git`
- macOS: `xcode-select --install` and `brew install cmake`

## Get the code

Clone this repository **and its submodule** (the CAS BACnet Stack):

```bash
git clone --recursive https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP.git
cd BACnetProfileExample-B-SCHUB-CPP

# already cloned without --recursive? fetch the submodule:
git submodule update --init --recursive
```

## Build

This example links the CAS BACnet Stack as a prebuilt **STATIC** library. Build
the library once from the pinned submodule commit, then configure and build the
example against it:

```bash
tools/build-stack-static.sh BACnetProfileExample-B-SCHUB-CPP   # from the series root; builds
                                                                 # submodules/cas-bacnet-stack/bin/...
cmake -B build -S . -DCAS_BACNET_STACK_LINK=STATIC
cmake --build build --config Release
```

> **The stack library build takes a few minutes** the first time - it compiles
> the entire CAS BACnet Stack (~600 source files) once, via the stack's own
> project files (`msbuild` on Windows, `make` on Linux). The example itself
> (`main.cpp` + `common/`) then builds in seconds against that library.
>
> ```bash
> cmake --build build --config Release --parallel
> ```

If your CAS BACnet Stack lives somewhere other than the bundled submodule, point
CMake at it: `cmake -B build -S . -D CAS_STACK_DIR=/path/to/cas-bacnet-stack`.

### Link mode

This example links the stack through the `CASBACnetStack::Adapter` CMake target
(`submodules/cas-bacnet-stack/adapters/cpp`) in **STATIC** mode -
`-DCAS_BACNET_STACK_LINK=STATIC` links the prebuilt
`CASBACnetStack_x64_Release.lib` / `libCASBACnetStack_x64_Release.a` built by
`tools/build-stack-static.sh` above. Every mode requires calling
`LoadBACnetFunctions()` once at the top of `main()` before any other
`BACnetStack_*` call.

On MSVC the adapter also forces the static CRT (`/MT`) to match how the library is
built.

The adapter also offers a **SOURCE** mode (compiles the stack's `source/*.cpp`
straight into the executable, no library build step) - this example is built
and published in **STATIC** mode only.

## Run

```bash
# Linux / macOS
./build/BACnetExampleBSCHUB

# Windows
.\build\Release\BACnetExampleBSCHUB.exe
```

Expected output:

```
BACnet B-SCHUB (BACnet/SC Hub) Example - C++ v1.0.0
CAS BACnet Stack version: 6.0.21.0
Common helper (common/) version: 2.5.0
FYI: Listening for BACnet/IP on UDP port 47808.
TX 21 bytes to 192.168.3.255:47808 (broadcast)
FYI: Device 389022 ("Rainbow") ready. Vendor ID 389. Press 'h' for help.
FYI: BACnet/SC hub function is CONFIGURED on Network Port 2 (Vermilion 2) but its WebSocket/TLS transport is a documented stub - see README.md "BACnet/SC support" and TODO.md.
RX 21 bytes from 192.168.3.64:47808
BACnet/SC: stack asked to LISTEN for inbound WebSocket connections on wss://0.0.0.0:47819/ - STUB, no WebSocket/TLS transport is implemented (see TODO.md). The hub function is configured but will not accept any real SC node connection until a transport is added.
```

The `RX` line depends on what else is on your network, so it may appear
earlier, later, or not at all on a quiet subnet. The device is ready as soon as
the `Device ... ready` line prints. The `BACnet/SC: stack asked to LISTEN...`
line only appears once (it would otherwise repeat every `Tick()` the stack
retries).

The device listens on UDP **47808** (BACnet/IP). Allow that port through your
firewall. To use a different port, pass `--port`.

### Command-line options

| Option | Default | Meaning |
|--------|---------|---------|
| `--port <n>` | `47808` | UDP port to listen on (BACnet/IP). |
| `--deviceID <n>` | `389022` | The device's BACnet instance number (BACnet requires this to be configurable). |
| `--help`, `-h` | - | Show usage and exit. |
| `--version` | - | Print the example, stack, and `common/` helper versions, then exit. |

### Interactive commands

While the example runs, these keys are available (shared across all examples in
the series):

| Key | Action |
|-----|--------|
| `h` | Show the version information and this command list. |
| `q` | Quit. |
| up arrow | Increase Analog Input 1 (`Bronze`) by 1.1. |
| down arrow | Decrease Analog Input 1 (`Bronze`) by 1.1. |

## Verify

### Over BACnet/IP (verified, real client)

Verified with `bacpypes3` (a real Python BACnet client, not a hand check)
against a running instance of this example:

1. **Discover** - `who_is()` returns an **I-Am** from instance **389022**
   (vendor **389**).
2. **Read the Device** - ReadProperty `389022` `Object_Name` = `"Rainbow"`;
   `Vendor_Identifier` = `389`; `Model_Name` = `"CAS BACnet Stack Example -
   B-SCHUB"`.
3. **Read Analog Input 1** - `Present_Value` = `21.5`.
4. **Read Network Port 2** - `Object_Name` = `"Vermilion 2"`; `Network_Type` =
   `11` (`secureConnect`) - confirming the BACnet/SC Network Port object is
   present and correctly typed, over ordinary BACnet/IP ReadProperty.

You can repeat this with any BACnet client - [CAS BACnet
Explorer](https://store.chipkin.com/products/tools/cas-bacnet-explorer),
[YABE](https://sourceforge.net/projects/yetanotherbacnetexplorer/), or
[Wireshark](https://www.wireshark.org/) with the `bvlc` filter.

### Over BACnet/SC (NOT wire-verified - flagged, not faked)

**This was not verified on the wire**, and this README says so rather than
implying otherwise: verifying an actual SC node connecting to this hub and
reading its Device object requires a second BACnet/SC-capable process (a real
WebSocket/TLS client, or another SC-capable BACnet stack/tool) and, on this
example's own side, a working WebSocket/TLS transport behind the stub
callbacks - see [BACnet/SC support](#bacnetsc-support-read-this-first) above.
Neither was available in this session. What **is** verified instead: the SC
protocol/configuration calls all return success at runtime
(`BACnetStack_SetBACnetSCUuid`, `BACnetStack_AddBACnetSCAcceptUri`,
`BACnetStack_SetBACnetSCHubFunctionConfig` - every one is
`if (!BACnetStack_...) return 1;`-guarded and none trips), and the stack's own
state machine calls back into this example asking to listen on the configured
`wss://` URI exactly as documented - i.e. the code path is real and exercised
up to the transport boundary, not merely code-reviewed.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Console prints a line every time `BACnetStack_Tick()` runs about listening for WebSocket connections | Fixed by design: `CallbackSCStartListening` only logs **once** (a static `warned` flag), even though the stack retries it every `Tick()` while it keeps returning `false`. If you see it repeating, check you're running the version in this repo. |
| No BACnet/SC node ever connects | Expected - the WebSocket/TLS transport is a documented stub in this build. See [BACnet/SC support](#bacnetsc-support-read-this-first) and [`TODO.md`](TODO.md). |
| CMake error: *"CAS BACnet Stack adapter not found under: ..."* | Submodules not initialized. Run `git submodule update --init --recursive` (or pass `-D CAS_STACK_DIR=...`). |
| CMake error: *"CAS_BACNET_STACK_LINK=STATIC needs a prebuilt CAS BACnet Stack library"* | The static library has not been built yet. Run `tools/build-stack-static.sh BACnetProfileExample-B-SCHUB-CPP` from the series root, then re-run CMake. |
| The device starts and prints `TX ... (broadcast)`, but no client ever sees it | Check the IP in that `TX` line against the subnet your BACnet client is on. The example picks the **first non-loopback adapter** the OS reports. |
| `CASBACnetStackDLL.h: No such file or directory` | Submodules not checked out. |
| Windows: *"No CMAKE_CXX_COMPILER could be found"* | Install Visual Studio with the "Desktop development with C++" workload, then re-run from a fresh terminal. |
| First build seems stuck for minutes | Normal - it's compiling ~600 stack files. Only the first build is slow. |
| `git submodule update` fails with *Permission denied* / *repository not found* | The CAS BACnet Stack submodule is a **private** repo. You need a stack licence and access granted to your GitHub account. |
| App prints *"Failed to bind UDP port 47808"* | Another BACnet program is already using 47808. Stop it, or run with `--port <n>`. |
| DeviceCommunicationControl `disable` returns an error | Expected. The plain `disable` value is deprecated at Protocol_Revision >= 20; use `disable-initiation` instead. |
| Client sends Who-Is but sees no I-Am | Firewall is blocking UDP 47808, or the client and device are on different subnets. |

## Extending the example

See [B-ASC's README](https://github.com/chipkin/BACnetProfileExample-B-ASC-CPP#extending-the-example)
for the full "adding a new object instance" recipe and why a half-added object
looks healthy and is not - it applies unchanged here.

**Implement the BACnet/SC transport for real.** See [`TODO.md`](TODO.md) for
exactly what to add: a WebSocket client/listener (RFC 6455 framing over TCP)
plus a TLS layer wired to `CallbackInitiateWebsocket` /
`CallbackSCStartListening` / their disconnect counterparts, reporting real
status through `BACnetStack_SetBACnetSCWebSocketStatus`, and File objects +
`BACnetStack_SetBACnetSCCertificateFileObjects` for the operational
certificate.

**Require a password for DeviceCommunicationControl** - set `DCC_PASSWORD` in
`main.cpp` to a non-empty string; the callback then rejects mismatches with
`password-failure`.

## Objects and properties

<!-- OBJECTS-PROPERTIES:BEGIN (generated by tools/gen-objects-properties.py from docs/objects.json - do not edit here) -->
Every object this example creates, and every REQUIRED property of each (per ANSI/ASHRAE 135-2024 clause 12 and the stack's `docs/property-profile-reference.md`), plus the optional properties the example turns on. **Served by** says who answers a ReadProperty: the **stack** generates it, or the **app** serves it from a `GetProperty*` callback in `main.cpp`. A ⚠ row is a required property the app does not serve and the stack would fill with a default - that is a defect, not a feature.

### Device 389022 "Rainbow" - vendor 389 (Chipkin Automation Systems); instance configurable with --deviceID. The properties in 'accepted' are not served from a GetProperty callback because the stack itself is the source of truth for them - Protocol_Revision/Protocol_Version are stack build constants, Protocol_Services_Supported/Protocol_Object_Types_Supported are computed from the BACnetStack_SetServiceEnabled/AddObject calls this example already makes, Object_List and Device_Address_Binding are live stack-maintained tables, System_Status/Database_Revision/Max_APDU_Length_Accepted/Segmentation_Supported/APDU_Timeout/Number_Of_APDU_Retries are the stack's own configuration defaults for a device this example does not override

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| System_Status | BACnetDeviceStatus | stack default, accepted (Generic Enumerated default: `0`) | no |
| Vendor_Name | CharacterString | app | no |
| Vendor_Identifier | Unsigned16 | app | no |
| Model_Name | CharacterString | app | no |
| Firmware_Revision | CharacterString | app | no |
| Application_Software_Version | CharacterString | app | no |
| Description *(optional, enabled)* | CharacterString | app | no |
| Protocol_Version | Unsigned | stack default, accepted (`BACNET_PROTOCOL_VERSION`) | no |
| Protocol_Revision | Unsigned | stack default, accepted (`BACNET_PROTOCOL_REVISION`) | no |
| Protocol_Services_Supported | BACnetServicesSupported | stack default, accepted (computed from which services are enabled) | no |
| Protocol_Object_Types_Supported | BACnetObjectTypesSupported | stack default, accepted (computed from which object types are supported) | no |
| Object_List | BACnetARRAY[N] of BACnetObjectIdentifier | stack default, accepted (None known - a read fails with `unknown-property` or an empt) | no |
| Max_APDU_Length_Accepted | Unsigned | stack default, accepted (`CAS_BACNET_DEVICE_DEFAULT_MAX_APDU_LENGTH_ACCEPTED`) | no |
| Segmentation_Supported | BACnetSegmentation | stack default, accepted (`BACnetSegmentation::noSegmentation`) | no |
| APDU_Timeout | Unsigned | stack default, accepted (`CAS_BACNET_DEVICE_DEFAULT_APDU_TIMEOUT`) | no |
| Number_Of_APDU_Retries | Unsigned | stack default, accepted (`CAS_BACNET_DEVICE_DEFAULT_NUMBER_OF_APDU_RETRIES`) | no |
| Device_Address_Binding | BACnetLIST of BACnetAddressBinding | stack default, accepted (the live Device_Address_Binding (DAB) table) | no |
| Database_Revision | Unsigned | stack default, accepted (Generic UnsignedInteger default: `0`) | no |

### Analog Input 1 "Bronze" - REAL, degrees Celsius; starts at 21.5; read-only

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Present_Value | Real | app | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Event_State | BACnetEventState | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Units | BACnetEngineeringUnits | app | no |

### Binary Input 1 "Emerald" - starts inactive; read-only

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Present_Value | BACnetBinaryPV | app | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Event_State | BACnetEventState | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Polarity | BACnetPolarity | app | no |

### Multi-state Input 1 "Hot Pink" - state 1 of 3: On, Off, Auto; read-only

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Present_Value | Unsigned | app | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Event_State | BACnetEventState | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Number_Of_States | Unsigned | app | no |
| State_Text *(optional, enabled)* | BACnetARRAY[N] of CharacterString | app | no |

### Network Port 1 "Vermilion" - BACnet/IP; kept active throughout so this example stays discoverable over plain BACnet/IP regardless of the BACnet/SC transport outcome below. Network_Type and Protocol_Level are set from BACnetStack_AddNetworkPortObject()'s arguments (IPv4, BACnet Application) at start-up, not a GetProperty callback like the object's other app-served rows; Changes_Pending is likewise computed and answered natively by the stack's Network Port object. Reliability has no fault condition this example detects, so it is accepted at the generic default (normal)

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Reliability | BACnetReliability | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Network_Type | BACnetNetworkType | app | no |
| Protocol_Level | BACnetProtocolLevel | app | no |
| Changes_Pending | Boolean | app | no |

### Network Port 2 "Vermilion 2" - BACnet/SC (Network_Type = secureConnect(11)); hosts the NM-SCH-B hub function - see README "BACnet/SC support". The hub function's BACnet-level configuration (UUID, accept URI, SetBACnetSCHubFunctionConfig) is real and stack-verified; the underlying WebSocket/TLS transport is a documented stub (RegisterCallbackInitiateWebsocket/DisconnectWebsocket/SCStartListening/SCStopListening all log and decline - see main.cpp section 2c and TODO.md), so this Network Port never reaches a connected SC node in this build. Network_Type/Protocol_Level are set from BACnetStack_AddNetworkPortObject()'s arguments at start-up, same as Network Port 1. Reliability is accepted at the generic default (normal) for the same reason as Network Port 1

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Reliability | BACnetReliability | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Network_Type | BACnetNetworkType | app | no |
| Protocol_Level | BACnetProtocolLevel | app | no |
| Changes_Pending | Boolean | app | no |

<!-- OBJECTS-PROPERTIES:END -->

## The BACnet profile example series

<!-- PROFILE-TABLE:BEGIN (generated from cas-bacnet-stack-examples/docs/profile-table.md - do not edit here) -->
The CAS BACnet Stack supports every standardized device profile in ASHRAE 135-2024 Annex L. One example repository per profile shows how. ✅ = the required BIBB (service) is supported by the CAS BACnet Stack; the **Example** column is the state of that profile's tutorial repository.

### Controllers (Annex L.4)

| Profile | Example | Required BIBBs (services) |
|---|---|---|
| **B-SS** Smart Sensor | [B-SS-CPP](https://github.com/chipkin/BACnetProfileExample-B-SS-CPP) ✅ | ✅ DS-RP-B · ✅ DM-DDB-B · ✅ DM-DOB-B |
| **B-SA** Smart Actuator | [B-SA-CPP](https://github.com/chipkin/BACnetProfileExample-B-SA-CPP) ✅ | ✅ DS-RP-B · ✅ DS-WP-B · ✅ DM-DDB-B · ✅ DM-DOB-B |
| **B-ASC** Application Specific Controller | [B-ASC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ASC-CPP) ✅ · [B-ASC-Node](https://github.com/chipkin/BACnetProfileExample-B-ASC-Node) ✅ | ✅ DS-RP-B · ✅ DS-WP-B · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B |
| **B-AAC** Advanced Application Controller | [B-AAC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AAC-CPP) ✅ | ✅ DS-RP-B · ✅ DS-RPM-B · ✅ DS-WP-B · ✅ DS-WPM-B · ✅ AE-N-I-B · ✅ AE-ACK-B · ✅ AE-INFO-B · ✅ AE-CRL-B · ✅ SCHED-I-B · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B · ✅ DM-RD-B |
| **B-BC** Building Controller | [B-BC-CPP](https://github.com/chipkin/BACnetProfileExample-B-BC-CPP) 📝 | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-RPM-B · ✅ DS-WP-A · ✅ DS-WP-B · ✅ DS-WPM-B · ✅ AE-N-I-B · ✅ AE-ACK-B · ✅ AE-INFO-B · ✅ AE-CRL-B · ✅ SCHED-E-B · ✅ T-VMT-I-B · ✅ T-ATR-B · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B · ✅ DM-RD-B · ✅ DM-BR-B |

### Life safety controllers (Annex L.5)

| Profile | Example | Required BIBBs (services) |
|---|---|---|
| **B-LSC** Life Safety Controller | [B-LSC-CPP](https://github.com/chipkin/BACnetProfileExample-B-LSC-CPP) 📝 | ✅ DS-RP-B · ✅ DS-RPM-B · ✅ DS-WP-B · ✅ DS-WPM-B · ✅ DS-COV-B · ✅ AE-LS-B · ✅ AE-ACK-B · ✅ AE-INFO-B · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B · ✅ DM-RD-B |
| **B-ALSC** Advanced Life Safety Controller | [B-ALSC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ALSC-CPP) 📝 | ✅ DS-RP-B · ✅ DS-RPM-B · ✅ DS-WP-B · ✅ DS-WPM-B · ✅ DS-COV-B · ✅ AE-LS-B · ✅ AE-ACK-B · ✅ AE-INFO-B · ✅ AE-EL-I-B · ✅ SCHED-I-B · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B · ✅ DM-RD-B |

### Access control controllers (Annex L.6)

| Profile | Example | Required BIBBs (services) |
|---|---|---|
| **B-ACC** Access Control Controller | [B-ACC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACC-CPP) 📝 | ✅ DS-RP-B · ✅ DS-RPM-B · ✅ DS-WP-B · ✅ DS-WPM-B · ✅ DS-COV-B · ✅ DS-ACUC-B · ✅ DS-ACSC-B · ✅ AE-AC-B · ✅ AE-ACK-B · ✅ AE-INFO-B · ✅ AE-EL-I-B · ✅ SCHED-I-B · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B · ✅ DM-RD-B · ✅ DM-BR-B |
| **B-AACC** Advanced Access Control Controller | [B-AACC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AACC-CPP) 📝 | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-RPM-B · ✅ DS-WP-A · ✅ DS-WP-B · ✅ DS-WPM-B · ✅ DS-COV-A · ✅ DS-COV-B · ✅ DS-ACAD-A · ☐ DS-ACCDI-A · ✅ DS-ACUC-B · ✅ DS-ACSC-B · ✅ AE-AC-B · ✅ AE-ACK-B · ✅ AE-INFO-B · ✅ AE-EL-I-B · ✅ SCHED-I-B · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B · ✅ DM-RD-B · ✅ DM-BR-B |

### Lighting controllers (Annex L.11)

| Profile | Example | Required BIBBs (services) |
|---|---|---|
| **B-LD** Lighting Device | [B-LD-CPP](https://github.com/chipkin/BACnetProfileExample-B-LD-CPP) ✅ | ✅ DS-RP-B · ✅ DS-WP-B · ✅ DS-LO-B / DS-BLO-B · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B |
| **B-LS** Lighting Supervisor | [B-LS-CPP](https://github.com/chipkin/BACnetProfileExample-B-LS-CPP) 📝 | ✅ DS-RP-B · ✅ DS-WP-A · ✅ DS-WP-B · ✅ DS-WG-E-B · ✅ DS-ALO-A · ✅ SCHED-E-B · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B |

### Elevator controllers (Annex L.13)

| Profile | Example | Required BIBBs (services) |
|---|---|---|
| **B-EM** Elevator Monitor | [B-EM-CPP](https://github.com/chipkin/BACnetProfileExample-B-EM-CPP) 📝 | ✅ DS-RP-B · ✅ DS-RPM-B · ✅ DS-COV-B · ✅ DS-COVM-B · ✅ AE-N-I-B · ✅ AE-ACK-B · ✅ AE-INFO-B · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B |
| **B-EC** Elevator Controller | [B-EC-CPP](https://github.com/chipkin/BACnetProfileExample-B-EC-CPP) 📝 | ✅ DS-RP-B · ✅ DS-RPM-B · ✅ DS-WP-B · ✅ DS-WPM-B · ✅ DS-COV-B · ✅ DS-COVM-B · ✅ AE-N-I-B · ✅ AE-ACK-B · ✅ AE-INFO-B · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B · ✅ DM-RD-B |
| **B-AEC** Advanced Elevator Controller | [B-AEC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AEC-CPP) 📝 | ✅ DS-RP-B · ✅ DS-RPM-B · ✅ DS-WP-B · ✅ DS-WPM-B · ✅ DS-COV-B · ✅ DS-COVM-B · ✅ AE-N-I-B · ✅ AE-ACK-B · ✅ AE-INFO-B · ✅ AE-EL-I-B · ✅ SCHED-I-B · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B · ✅ DM-OCD-B · ✅ DM-RD-B · ✅ DM-BR-B |

### Authentication and authorization (Annex L.14)

| Profile | Example | Required BIBBs (services) |
|---|---|---|
| **B-AS** Authorization Server | [B-AS-CPP](https://github.com/chipkin/BACnetProfileExample-B-AS-CPP) 📝 | ✅ DS-RP-B · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ AA-AS-B |

### Miscellaneous (Annex L.7, combinable with any one family)

| Profile | Example | Required BIBBs (services) |
|---|---|---|
| **B-BBMD** Broadcast Management Device | [B-BBMD-CPP](https://github.com/chipkin/BACnetProfileExample-B-BBMD-CPP) ✅ | ✅ DS-RP-B · ✅ DS-WP-B · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ NM-BBMDC-B |
| **B-ACDC** Access Control Door Controller | [B-ACDC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACDC-CPP) ✅ | ✅ DS-RP-B · ✅ DS-WP-B · ✅ DS-ACAD-B · ✅ DM-DDB-B · ✅ DM-DOB-B |
| **B-ACCR** Access Control Credential Reader | [B-ACCR-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACCR-CPP) 📝 | ✅ DS-RP-B · ✅ DS-WP-B · ✅ DS-COV-B · ✅ DS-ACCDI-B · ✅ DM-DDB-B · ✅ DM-DOB-B |
| **B-RTR** Router | [B-RTR-CPP](https://github.com/chipkin/BACnetProfileExample-B-RTR-CPP) 📝 | ✅ DS-RP-B · ✅ DS-WP-B · ✅ DM-DDB-A · ✅ DM-DOB-B · ✅ DM-LM-B · ✅ NM-RC-B |
| **B-GW** Gateway | [B-GW-CPP](https://github.com/chipkin/BACnetProfileExample-B-GW-CPP) 📝 | ✅ DS-RP-B · ✅ DS-WP-B · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ GW-EO-B / GW-VN-B |
| **B-DAP** Device Address Proxy | [B-DAP-CPP](https://github.com/chipkin/BACnetProfileExample-B-DAP-CPP) 📝 | ✅ DS-RP-B · ✅ DS-WP-B · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DAB-B |
| **B-SCHUB** BACnet/SC Hub | [B-SCHUB-CPP](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP) 📝 | ✅ DS-RP-B · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ NM-SCH-B |
| **B-GENERAL** General device (Annex L.8) | *(satisfied by every example above)* | ✅ DS-RP-B · ✅ DM-DDB-B · ✅ DM-DOB-B |

### Operator interfaces and workstations (Annex L.1–L.3, L.9–L.10, L.12) — client-side profiles

| Profile | Example | Required BIBBs (services) |
|---|---|---|
| **B-OD** Operator Display | [B-OD-CPP](https://github.com/chipkin/BACnetProfileExample-B-OD-CPP) ✅ | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-WP-A · ✅ DS-V-A · ✅ DS-M-A · ✅ AE-N-A · ✅ AE-VN-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B |
| **B-OWS** Operator Workstation | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-WP-A · ✅ DS-V-A · ✅ DS-M-A · ✅ AE-N-A · ✅ AE-ACK-A · ✅ AE-AS-A · ✅ AE-VM-A · ✅ AE-VN-A · ✅ SCHED-VM-A · ✅ T-V-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-MTS-A |
| **B-AWS** Advanced Operator Workstation | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-WP-A · ✅ DS-WPM-A · ✅ DS-AV-A · ✅ DS-AM-A · ✅ AE-N-A · ✅ AE-ACK-A · ✅ AE-AS-A · ✅ AE-AVM-A · ✅ AE-AVN-A · ✅ AE-ELVM-A · ✅ SCHED-AVM-A · ✅ T-AVM-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-ANM-A · ✅ DM-ADM-A · ✅ DM-DOB-B · ✅ DM-DCC-A · ✅ DM-MTS-A · ✅ DM-OCD-A · ✅ DM-RD-A · ✅ DM-BR-A · ✅ DM-DDA-A · ✅ NM-CC-A · ✅ AR-AVM-A |
| **B-XAWS** Extended Advanced Operator Workstation | planned | ✅ union of B-AWS + B-AACWS + B-ALWS + B-AEWS |
| **B-LSAP** Life Safety Annunciator Panel | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-WP-A · ✅ DS-LSV-A · ✅ AE-N-A · ✅ AE-LS-A · ✅ AE-ACK-A · ✅ AE-LSVN-A |
| **B-LSWS** Life Safety Workstation | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-WP-A · ✅ DS-WPM-A · ✅ DS-LSV-A · ✅ DS-LSM-A · ✅ AE-N-A · ✅ AE-LS-A · ✅ AE-ACK-A · ✅ AE-AS-A · ✅ AE-LSVM-A · ✅ AE-LSAVN-A · ✅ AE-ELV-A · ✅ SCHED-VM-A · ✅ T-V-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-ANM-A · ✅ DM-ADM-A · ✅ DM-DOB-B · ✅ DM-DCC-A · ✅ DM-MTS-A · ✅ DM-OCD-A · ✅ DM-RD-A · ✅ DM-BR-A |
| **B-ALSWS** Advanced Life Safety Workstation | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-WP-A · ✅ DS-WPM-A · ✅ DS-LSAV-A · ✅ DS-LSAM-A · ✅ AE-N-A · ✅ AE-LS-A · ✅ AE-ACK-A · ✅ AE-AS-A · ✅ AE-LSAVM-A · ✅ AE-LSAVN-A · ✅ AE-ELVM-A · ✅ SCHED-AVM-A · ✅ T-AVM-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-ANM-A · ✅ DM-ADM-A · ✅ DM-DOB-B · ✅ DM-DCC-A · ✅ DM-MTS-A · ✅ DM-OCD-A · ✅ DM-RD-A · ✅ DM-BR-A · ✅ AR-AVM-A |
| **B-ACSD** Access Control Security Display | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-WP-A · ✅ DS-WPM-A · ✅ DS-ACV-A · ✅ DS-ACM-A · ✅ AE-N-A · ✅ AE-AC-A · ✅ AE-ACK-A · ✅ AE-AS-A · ✅ AE-ACAVN-A · ✅ AE-ELV-A · ✅ SCHED-VM-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-MTS-A |
| **B-ACWS** Access Control Workstation | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-WP-A · ✅ DS-WPM-A · ✅ DS-ACAV-A · ✅ DS-ACM-A · ✅ DS-ACUC-A · ✅ AE-N-A · ✅ AE-AC-A · ✅ AE-ACK-A · ✅ AE-AS-A · ✅ AE-ACVM-A · ✅ AE-ACAVN-A · ✅ AE-ELV-A · ✅ SCHED-VM-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-ANM-A · ✅ DM-ADM-A · ✅ DM-DOB-B · ✅ DM-DCC-A · ✅ DM-MTS-A · ✅ DM-OCD-A · ✅ DM-RD-A · ✅ DM-BR-A |
| **B-AACWS** Advanced Access Control Workstation | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-WP-A · ✅ DS-WPM-A · ✅ DS-ACAV-A · ✅ DS-ACAM-A · ✅ DS-ACUC-A · ✅ DS-ACSC-A · ✅ AE-N-A · ✅ AE-AC-A · ✅ AE-ACK-A · ✅ AE-AS-A · ✅ AE-ACAVM-A · ✅ AE-ACAVN-A · ✅ AE-ELVM-A · ✅ SCHED-AVM-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-ANM-A · ✅ DM-ADM-A · ✅ DM-DOB-B · ✅ DM-DCC-A · ✅ DM-MTS-A · ✅ DM-OCD-A · ✅ DM-RD-A · ✅ DM-BR-A · ✅ AR-AVM-A |
| **B-LOD** Lighting Operator Display | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-WP-A · ✅ DS-LV-A · ✅ DS-WG-A · ✅ DS-ALO-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B |
| **B-ALWS** Advanced Lighting Workstation | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-WP-A · ✅ DS-WPM-A · ✅ DS-LAV-A · ✅ DS-LAM-A · ✅ DS-WG-A · ✅ DS-ALO-A · ✅ AE-N-A · ✅ AE-ACK-A · ✅ AE-AS-A · ✅ AE-AVM-A · ✅ AE-AVN-A · ✅ AE-ELVM-A · ✅ SCHED-AVM-A · ✅ T-AVM-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-ANM-A · ✅ DM-ADM-A · ✅ DM-DOB-B · ✅ DM-DCC-A · ✅ DM-MTS-A · ✅ DM-OCD-A · ✅ DM-RD-A · ✅ DM-BR-A |
| **B-LCS** Lighting Control Station | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-WP-A · ✅ DS-LO-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B |
| **B-ALCS** Advanced Lighting Control Station | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-WP-A · ✅ DS-WPM-A · ✅ DS-WG-A · ✅ DS-ALO-A · ✅ SCHED-E-B · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B · ✅ DM-DCC-B · ✅ DM-TS-B / DM-UTC-B |
| **B-ED** Elevator Display | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-WP-A · ✅ DS-EV-A · ✅ AE-N-A · ✅ AE-ACK-A · ✅ AE-EVN-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-DOB-B |
| **B-EWS** Elevator Workstation | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-WP-A · ✅ DS-WPM-A · ✅ DS-COVM-A · ✅ DS-EV-A · ✅ DS-EM-A · ✅ AE-N-A · ✅ AE-ACK-A · ✅ AE-AS-A · ✅ AE-EVM-A · ✅ AE-EAVN-A · ✅ SCHED-VM-A · ✅ T-V-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-ANM-A · ✅ DM-ADM-A · ✅ DM-DOB-B · ✅ DM-DCC-A · ✅ DM-MTS-A |
| **B-AEWS** Advanced Elevator Workstation | planned | ✅ DS-RP-A · ✅ DS-RP-B · ✅ DS-RPM-A · ✅ DS-WP-A · ✅ DS-WPM-A · ✅ DS-COVM-A · ✅ DS-EAV-A · ✅ DS-EAM-A · ✅ AE-N-A · ✅ AE-ACK-A · ✅ AE-AS-A · ✅ AE-EAVM-A · ✅ AE-EAVN-A · ✅ AE-ELVM-A · ✅ SCHED-AVM-A · ✅ T-AVM-A · ✅ DM-DDB-A · ✅ DM-DDB-B · ✅ DM-ANM-A · ✅ DM-ADM-A · ✅ DM-DOB-B · ✅ DM-DCC-A · ✅ DM-MTS-A · ✅ DM-OCD-A · ✅ DM-RD-A · ✅ DM-BR-A |

Profile definitions: ANSI/ASHRAE 135-2024 Annex L. BIBB definitions: Annex K. Get the stack: <https://store.chipkin.com/services/stacks/bacnet-stack>.
<!-- PROFILE-TABLE:END -->


## Footprint

Release-build sizes and start-up timing, from the latest tagged release's CI
run (`metrics-windows.json` / `metrics-linux.json`), both built with
`CAS_BACNET_STACK_LINK=STATIC`:

<!-- METRICS -->
| Platform | Binary | Size | SHA-256 (prefix) | Start-up to `ready` | Stack commit | Link mode | Compiler |
|---|---|---|---|---|---|---|---|
| Windows x64 (windows-2022) | `BACnetExampleBSCHUB.exe` | 3,255,296 bytes (~3.1 MiB) | `1636501694af33da` | 63 ms | `abd4cee1` | STATIC | Visual Studio 17 2022 |
| Linux x64 (ubuntu-latest) | `BACnetExampleBSCHUB` | 39,992 bytes (~39 KiB) | `53e2acfb77d8102c` | 8 ms | `abd4cee1` | STATIC | `/usr/bin/c++` |

From release [v1.0.0](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases/tag/v1.0.0) (`metrics-windows.json` / `metrics-linux.json`).

## References

- **ANSI/ASHRAE Standard 135** (BACnet) - the protocol standard. Object model
  (Clause 12), services (Clause 16), BACnet/SC (Annex AB), device profiles
  (Annex L). Purchase / preview via the
  [ASHRAE store](https://www.ashrae.org/technical-resources/standards-and-guidelines).
- **What is BACnet?** - Chipkin's introduction:
  <https://docs.chipkin.com/protocols/bacnet/>.
- **CAS BACnet Stack** - product page and documentation:
  <https://store.chipkin.com/services/stacks/bacnet-stack>.
- **CAS BACnet Stack BACnet/SC Manual** -
  `submodules/cas-bacnet-stack/docs/CAS BACnet Stack - BACnet SC Manual_v6.md`
  (private, part of the stack submodule).
- **CAS BACnet Explorer** - client for testing this device:
  <https://store.chipkin.com/products/tools/cas-bacnet-explorer>.
- **B-ASC (Application Specific Controller) example** - the seed this builds on:
  <https://github.com/chipkin/BACnetProfileExample-B-ASC-CPP>.
- **Shared helper used by this example** - [`common/README.md`](common/README.md).

## Use this in your own project

This repository is self-contained: clone it (with the submodule) and build, then
copy what you need into your product. The example source code is dedicated to the
public domain under [CC0-1.0](LICENSE) - use it for anything, no attribution
required. The CAS BACnet Stack is a separate, commercially licensed product and
is not covered by CC0.

### Calling `BACnetStack_Tick()` in a real product

The example calls `Tick()` in a tight loop with a 1 ms sleep. What the stack actually requires:

- **Call it regularly.** Every timer the stack owns - APDU retries/timeouts,
  the BACnet/SC connection state machines, DCC durations - advances only
  inside `Tick()`.
- **Single-threaded contract.** The stack contains no locking of any kind, and
  `Tick()` invokes your callbacks on the calling thread, synchronously. Call
  `Tick()` from exactly one thread.
- **Never block inside a callback**, including the BACnet/SC transport
  callbacks - `CallbackInitiateWebsocket` and `CallbackSCStartListening` must
  open the connection **asynchronously** and report status later through
  `BACnetStack_SetBACnetSCWebSocketStatus`, exactly as their doc comments say.

See also [CHANGELOG.md](CHANGELOG.md) and [TODO.md](TODO.md). Contributors and AI agents: [AGENTS.md](AGENTS.md) documents the repo conventions.
