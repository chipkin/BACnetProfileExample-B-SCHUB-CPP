# BACnet B-SCHUB (BACnet/SC Hub) - C++ example

A minimal, copy-paste-friendly example showing how to implement the BACnet
**B-SCHUB (BACnet Secure Connect Hub)** device profile in C++ using the
[CAS BACnet Stack](https://store.chipkin.com/services/stacks/bacnet-stack).
It listens on **BACnet/IP (UDP 47808)**, answers **ReadProperty**, responds to
**DeviceCommunicationControl**, is discoverable via **Who-Is / I-Am**, and
configures a **BACnet/SC hub function** Network Port - see
[BACnet/SC support](#bacnetsc-support-read-this-first) below for exactly what
that last part does and does not do in this build.

**[Download a prebuilt binary](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases)**
(Windows and Linux x64) - or build it yourself, see [Build](#build) below.

- **[TUTORIAL.md](TUTORIAL.md)** - how to extend this example (including what
  a real BACnet/SC transport needs) and how to review it for conformance.
  Read it when you start turning this into your own device.
- **[docs/PICS.md](docs/PICS.md)** - the Protocol Implementation Conformance
  Statement: every object, every property, and who answers it.

> **Versions:** this document describes **example v1.1.0**, built and verified
> against **CAS BACnet Stack 6.0.21** (`6.x` @ `abd4cee1`), at
> **Protocol_Revision 24**, with the vendored `common/` helper at **v2.6.0**.
> Running the example prints all three - if what it prints disagrees with this
> line, trust the program and check `CHANGELOG.md`.

## BACnet/SC support: read this first

This example is canonical for **F-SC**. **Both the BACnet/SC protocol and the
WebSocket/TLS transport underneath it are real and verified against real
peers** - a real BACnet/SC node connects to this hub, mutually authenticates
over TLS 1.3, and is discovered/read over BACnet/SC; this example can, in
turn, dial out to (and be discovered/relayed by) a real BACnet/SC hub. See
`TODO.md` for the genuine, documented limitations that remain (certificate
validation callbacks, hostname checking, CRLs - none of them bugs in this
example; see below).

**Architecture:** the CAS BACnet Stack owns the BACnet/SC *protocol* - the
Hello handshake, the hub/node/direct-connect connection state machines, BVLC
framing, certificate-object bookkeeping, and every SC-related Network Port
property. It does **not** own the transport. Verbatim, from the doc comment
on `BACnetStack_RegisterCallbackInitiateWebsocket` in `CASBACnetStackDLL.h`:

> "The stack implements no WebSocket or TLS itself."

The stack asks the **host application** to actually open, accept, and close raw
WebSocket(+TLS) connections through four callbacks
(`RegisterCallbackInitiateWebsocket`, `RegisterCallbackDisconnectWebsocket`,
`RegisterCallbackSCStartListening`, `RegisterCallbackSCStopListening`) and
expects real connection status reported back through
`BACnetStack_SetBACnetSCWebSocketStatus`; certificate validation and CSR
generation are likewise host callbacks. This example supplies all of that:
`sc_transport/` (below) for the WebSocket/TLS transport, and 4 read-only File
objects (see the device tree below) for the certificate/CSR content.

**What this example implements (both roles):**

- `BACnetStack_SetBACnetSCUuid` - the required device-wide SC UUID.
- A second Network Port object (2, "BACnet SC", `Network_Type = secureConnect
  (11)`) representing the BACnet/SC data link.
- `BACnetStack_AddBACnetSCAcceptUri` + `BACnetStack_SetBACnetSCHubFunctionConfig`
  - configures and **enables** the NM-SCH-B hub function with a `wss://` accept
  URI and a connection limit.
- `sc_transport/ScTransport` - a libwebsockets + OpenSSL (via vcpkg) transport:
  mutual TLS 1.3 only, subprotocol `hub.bsc.bacnet.org` (135-2024 AB.7.1),
  binary WebSocket framing, the 1497-byte ingress ceiling enforced, connection
  status queued and only ever reported to the stack from the main loop (never
  from inside an lws callback - see the class's header comment for why).
  Implements **both** roles:
  - **Listener** (hub-function accept role) - `StartListening()`/
    `StopListening()`. Verified with `tests/sc/hub_listener_test.py` (TLS 1.3
    + subprotocol negotiation, all required negative cases) and with a real
    peer (`BACnetSCCli.exe`, `Role=node`) completing Who-Is/I-Am/ReadProperty
    discovery of this device over BACnet/SC.
  - **Connector** (hub/node initiate role) - `Connect()`/`Disconnect()`. OFF
    by default (`--sc-hub-uri` turns it on - see [Command-line
    options](#command-line-options)); this hub-only example does not need one
    to answer a node's own requests (the hub function delivers locally). When
    enabled, verified against `tests/sc/fake_hub_server.py` and against a real
    hub (`BACnetSCCli.exe`, `Role=hub`), reaching hub-connector state
    `ConnectedPrimary`.
- `sc_transport/ScTransportRouter` - dispatches the stack's
  `ReceiveMessageForPort`/`SendMessageForPort` callbacks between BACnet/IP
  (Network Port 1) and BACnet/SC (Network Port 2, via `ScTransport`),
  alternating which datalink is polled first each tick so neither one can
  starve the other while both are busy.
- `scripts/generate-test-certs.cmake` - generates a throwaway lab CA + hub +
  node certificate set under `certs/` (gitignored; **lab testing only** - see
  [TUTORIAL.md](TUTORIAL.md#implement-the-bacnetsc-transport-for-real) for
  what a production certificate story needs).
- 4 read-only File objects (`Operational Certificate`/`CSR`/`Issuer Certificate Slot 1`/`Issuer Certificate Slot 2`) serving the
  hub's operational certificate, CSR, and issuer certificate (×2 slots) over
  AtomicReadFile - **never the private key**, which has no File object at
  all. Verified byte-for-byte over BACnet/IP against `certs/hub.crt`, with the
  private key confirmed unreachable through any File object instance.

**Known, documented limitations (not bugs in this example) - see
[`TODO.md`](TODO.md) for the full list:** certificate validation and CSR
generation are registered callbacks with **zero call sites** in this pinned
stack build (so they do nothing - this device's actual, and only, certificate
policy is CA-chain validation performed by OpenSSL/libwebsockets at TLS
handshake time); the connector skips server hostname checking (SC certificates
identify devices, not DNS hosts - the CA chain is still verified); no CRL
support; and the stack's SC ingress path is capped at 1497 bytes, one octet
short of Annex AB's 1600-octet minimum BVLC size a conformant hub should be
able to relay.

**The BACnet/IP Network Port (1, "BACnet IP") stays fully active** throughout,
so this example remains discoverable and testable over plain BACnet/IP
regardless of BACnet/SC, including while BACnet/SC peers are connected - see
[Verify](#verify) below.

## What is the B-SCHUB (BACnet/SC Hub) profile?

**B-SCHUB (BACnet Secure Connect Hub)**, defined in Annex L of ANSI/ASHRAE 135,
is a device that operates a **BACnet/SC hub function**: it accepts
WebSocket/TLS connections from BACnet/SC **nodes** and relays BACnet traffic
between them, the SC equivalent of a BACnet/IP broadcast domain. BACnet/SC
(Secure Connect) is the TLS/WebSocket-based BACnet transport added in ASHRAE
135-2020 Annex AB, designed to run over ordinary IT infrastructure (corporate
networks, VPNs, the Internet) with standard transport-layer security, unlike
BACnet/IP's plain UDP.

A B-SCHUB device answers **ReadProperty**, is discoverable, responds to
**DeviceCommunicationControl**, and operates the hub function above. It does
not have to support **WriteProperty**, **alarming / event reporting**,
**scheduling**, or **trending**, and this example implements none of them on
purpose.

**But it is still a full BACnet device.** Even a simple profile must present
the standard object model - a **Device** object, at least one **Network Port**
object (every device needs one; this device has two - see below), and its
objects - and each object must expose all of its **required properties**. The
CAS BACnet Stack generates most of those automatically (Object_Identifier,
Object_Type, Status_Flags, Object_List, Protocol_*, ...); this example supplies
the handful that are application-specific. The result is conformant for
**Protocol_Revision 24** on the BACnet/IP side; see above for the BACnet/SC
transport gap. [docs/PICS.md](docs/PICS.md) lists every property and who
answers it.

## DeviceCommunicationControl

`DeviceCommunicationControl` lets a management station tell a device to go quiet -
useful to silence a misbehaving or noisy device during commissioning - and later
to resume. The CAS BACnet Stack runs the actual enable/disable state machine and
the re-enable timer; this example's callback (`DeviceCommunicationControl` in
`main.cpp`) validates an optional password and logs what was asked. Note
(Protocol_Revision >= 20): the plain `disable` value is **deprecated** - even if
the callback accepts it, the stack rejects the request with
`service-request-denied`; the standard now expects `disable-initiation`.

The example ships with **no password** by default (accepts any request) - set
one at start-up with `--dcc-password <string>` (`common/` 2.6.0).

## The device this example creates

```
Device 389022  "Rainbow"   (Vendor 389 - Chipkin Automation Systems)
    │
    ├── Analog Input  1       "Bronze"        Present_Value  21.5    (REAL, degrees Celsius; read-only)
    ├── Binary Input  1       "Emerald"       Present_Value  inactive  (0 = inactive / 1 = active; read-only)
    ├── Multi-State Input 1   "Hot Pink"      Present_Value  1       (state, 1..3; read-only)
    ├── Network Port 1        "BACnet IP"     BACnet/IP - active, discoverable (required on every device)
    ├── Network Port 2        "BACnet SC"   BACnet/SC hub function - CONFIGURED, transport is real (both roles)
    ├── File 1                "Operational Certificate"         operational certificate (certs/hub.crt), read-only
    ├── File 2                "CSR"       certificate signing request (certs/hub.csr), read-only
    ├── File 3                "Issuer Certificate Slot 1"       issuer certificate slot 1 (certs/ca.crt), read-only
    └── File 4                "Issuer Certificate Slot 2"       issuer certificate slot 2 (certs/ca.crt), read-only
```

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
| DS-RPM-B | Data Sharing - ReadPropertyMultiple - B | ✅ |
| DM-DDB-B | Device Management - Dynamic Device Binding - B | ✅ |
| DM-DOB-B | Device Management - Dynamic Object Binding - B | ✅ |
| DM-DCC-B | Device Management - DeviceCommunicationControl - B | ✅ |
| NM-SCH-B | Network - Secure Connect Hub Function - B | ✅ configured AND transported (both hub-function/listener and connector roles are real - see above) |

### Services (executed / B-side)

| Service | Notes |
|---------|-------|
| ReadProperty | Responds to property reads (DS-RP-B). |
| ReadPropertyMultiple | Responds to multi-property reads in a single request (DS-RPM-B) - reuses the same per-property callbacks as ReadProperty. |
| Who-Is / I-Am | Answers Who-Is with I-Am, and broadcasts an I-Am on start-up (DM-DDB-B). |
| Who-Has / I-Have | Answers Who-Has with I-Have (DM-DOB-B). |
| DeviceCommunicationControl | Stops/resumes communication, optionally timed/passworded (DM-DCC-B). |
| BACnet/SC hub function | Protocol/state-machine AND WebSocket/TLS transport both real (NM-SCH-B) - see above. |
| AtomicReadFile | Serves the 4 certificate/CSR File objects, stream access, read-only. |

### Object types

| Object type | Instance | Name | Access |
|-------------|:--------:|------|--------|
| Device | 389022 | Rainbow | - |
| Analog Input | 1 | Bronze | read-only |
| Binary Input | 1 | Emerald | read-only |
| Multi-State Input | 1 | Hot Pink | read-only |
| Network Port | 1 | BACnet IP | - (BACnet/IP) |
| Network Port | 2 | BACnet SC | - (BACnet/SC) |
| File | 1 | Operational Certificate | read-only (operational certificate) |
| File | 2 | CSR | read-only (certificate signing request) |
| File | 3 | Issuer Certificate Slot 1 | read-only (issuer certificate slot 1) |
| File | 4 | Issuer Certificate Slot 2 | read-only (issuer certificate slot 2) |

Every required property of every object, and who answers it, is in
[docs/PICS.md](docs/PICS.md).

## Requires the CAS BACnet Stack (licensed product)

This example **builds against the CAS BACnet Stack, which is a commercial Chipkin
product** - it is not free or open source, and there is no public/trial build.
The stack is referenced here as the **private** git submodule
`submodules/cas-bacnet-stack`; you can only fetch and build it once you have a CAS
BACnet Stack license and access to that repository.

**To get the CAS BACnet Stack (and access to build this example), contact
Chipkin:** <https://store.chipkin.com/services/stacks/bacnet-stack> or
sales@chipkin.com.

You do not need a stack licence to *read* this example, or to run a
[prebuilt release binary](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases).
The licence is what lets you *build* it - that is the part the stack submodule
gates.

## What's in this repository

This is a **self-contained** project. It ships:

- `main.cpp` - the example device.
- `config.h`/`config.cpp` - the `--config <path>` file parser (example-local,
  not `common/` - see [Configuration file](#configuration-file) above).
- `example.conf` - a checked-in config-file template.
- `common/` - the shared helper (UDP, callbacks, CLI, keyboard) vendored in.
- `sc_transport/` - the real BACnet/SC WebSocket+TLS transport (libwebsockets
  + OpenSSL) and the stack&lt;-&gt;transport glue - see
  [`sc_transport/README.md`](sc_transport/README.md) for the wire-level
  contract.
- `scripts/generate-test-certs.cmake` - generates a throwaway lab CA + hub +
  node certificate set under `certs/` (gitignored).
- `tests/sc/` - the BACnet/SC verification scripts (see [Verify -> Over
  BACnet/SC](#over-bacnetsc-verified-against-a-real-peer) below).
- `vcpkg.json` - pins the `libwebsockets`/`openssl` dependencies `sc_transport/`
  needs (see [Prerequisites](#prerequisites) below).
- `CMakeLists.txt` - the build, the same on Windows, Linux, and macOS.
- `docs/PICS.md` - the conformance statement.
- `THIRD-PARTY-NOTICES.md` - licences for the bundled/linked third-party
  dependencies (libwebsockets, OpenSSL).
- `submodules/cas-bacnet-stack/` - the **CAS BACnet Stack as a git submodule**
  (private; requires a license - see above). Its sources are compiled into the
  executable, so there is no library or DLL to build, ship, or install.

## Prerequisites

- A C++17 compiler (MSVC, GCC, or Clang).
- CMake >= 3.15.
- Git (to fetch the stack submodule).
- **[vcpkg](https://vcpkg.io/)**, with the `VCPKG_ROOT` environment variable
  set - `sc_transport/`'s BACnet/SC transport depends on `libwebsockets` and
  `openssl` (via vcpkg's manifest mode, `vcpkg.json`), and CMake needs
  `VCPKG_ROOT` to find vcpkg's toolchain file automatically (see
  [Build](#build) below for exactly what that buys you). Visual Studio
  bundles a vcpkg install and sets `VCPKG_ROOT` for you inside a Developer
  Command Prompt; on Linux/macOS, or a bare Windows shell, install it
  yourself: <https://vcpkg.io/en/getting-started>.

### Windows

- **C++ compiler** - install
  [Visual Studio Community](https://visualstudio.microsoft.com/downloads/)
  (free) and select the **"Desktop development with C++"** workload (this
  also gives you a vcpkg install and a Developer Command Prompt with
  `VCPKG_ROOT` already set).
- **CMake** - from <https://cmake.org/download/>, or `winget install Kitware.CMake`.

### Linux / macOS

- Debian/Ubuntu: `sudo apt install build-essential cmake git ninja-build pkg-config`
- macOS: `xcode-select --install` and `brew install cmake ninja`
- vcpkg needs a handful of build tools of its own to compile `openssl`/
  `libwebsockets` from source (Perl, plus `libssl-dev`/build headers on some
  distros) - if `vcpkg install` reports a missing tool, install exactly the
  one it names and re-run the CMake configure step.

## Build

CMake only, and the same two commands on every platform (with `VCPKG_ROOT`
set - see [Prerequisites](#prerequisites) above):

```bash
git clone --recursive https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP.git
cd BACnetProfileExample-B-SCHUB-CPP

cmake -B build -S .
cmake --build build --config Release
```

Already cloned without `--recursive`? Run `git submodule update --init --recursive`
first - the build needs the stack submodule.

> **The first build takes longer than the series norm** - a few minutes to
> compile the CAS BACnet Stack (~600 source files) into the executable, **plus
> ~10-15 minutes the very first time vcpkg has to build OpenSSL from source**
> (`libwebsockets` is quick by comparison). vcpkg caches what it builds, so
> every build after that first one - even a from-scratch `rm -rf build` - skips
> straight to the stack compile. Rebuilds after that are incremental and take
> seconds.

If your CAS BACnet Stack lives somewhere other than the bundled submodule, point
CMake at it: `cmake -B build -S . -D CAS_STACK_DIR=/path/to/cas-bacnet-stack`.

### Generate lab test certificates

BACnet/SC's accept URIs are `wss://` (TLS) - the hub function needs a
certificate/key pair before it can actually listen (it still starts up and
answers BACnet/IP without one; see [Run](#run) below). Generate a throwaway
lab CA + hub + node certificate set under `certs/` (gitignored - **lab testing
only**, see [TUTORIAL.md](TUTORIAL.md#implement-the-bacnetsc-transport-for-real)
for what a production certificate story needs):

```bash
cmake --build build --target test-certs
# or directly:
cmake -P scripts/generate-test-certs.cmake
```

## Run

```bash
# Linux / macOS
./build/BACnetExampleBSCHUB

# Windows
.\build\Release\BACnetExampleBSCHUB.exe
```

Expected output (with `certs/` already generated - see [Generate lab test
certificates](#generate-lab-test-certificates) above):

```
BACnet B-SCHUB (BACnet/SC Hub) Example - C++ v1.1.0
CAS BACnet Stack version: 6.0.21.0
Common helper (common/) version: 2.6.0
FYI: Listening for BACnet/IP on UDP port 47808 (Network Port 1).
TX 21 bytes to 192.168.3.255:47808 (broadcast) (Network Port 1)
FYI: Device 389022 ("Rainbow") ready. Vendor ID 389. Press 'h' for help.
FYI: BACnet/SC hub function is CONFIGURED on Network Port 2 (BACnet SC), accept URI wss://0.0.0.0:47819/. Certificates: ./certs. See README.md "BACnet/SC support" for how to generate lab test certs.
RX 21 bytes from 192.168.3.64:47808 (Network Port 1)
BACnet/SC: listening for WebSocket/TLS connections on wss://0.0.0.0:47819/ (subprotocol "hub.bsc.bacnet.org", TLS 1.3, mutual auth)
```

Without `certs/`, the last line instead reads (and BACnet/IP keeps working
exactly the same either way):

```
BACnet/SC: cannot start listening on wss://0.0.0.0:47819/: certificate files are missing/unreadable (cert="./certs/hub.crt" key="./certs/hub.key" ca="./certs/ca.crt"). Run: cmake -P scripts/generate-test-certs.cmake
```

The `TX` line is the start-up I-Am the device broadcasts to announce itself. It
goes to the **local subnet broadcast** address (computed from the Network
Port's interface), not the global `255.255.255.255`. As clients talk to the
device you'll see `RX ... bytes from ...` and `TX ... bytes to ...` lines
showing the traffic - both over BACnet/IP and, once a node connects, over
BACnet/SC (tagged `SC peer "..."` instead of an IP:port). If `certs/` is
missing, the listener line instead explains what to run
(`cmake -P scripts/generate-test-certs.cmake`) and BACnet/IP keeps working.

The device listens on UDP **47808** (BACnet/IP). Allow that port through your
firewall. To use a different port, pass `--port` (see below).

> **A wall of red `Error:` lines at start-up is expected and is not your bug** -
> it is the stack's own debug logging (the device hearing its own broadcast I-Am,
> and BACnet/SC datalink bring-up). [TUTORIAL.md](TUTORIAL.md#troubleshooting)
> explains both.

### Command-line options

| Option | Default | Meaning |
|--------|---------|---------|
| `--port <n>` | `47808` | UDP port to listen on (BACnet/IP). |
| `--deviceID <n>` | `389022` | The device's BACnet instance number (BACnet requires this to be configurable). |
| `--sc-port <n>` | `47819` | WebSocket/TLS port for the BACnet/SC hub accept URI. |
| `--sc-cert-dir <dir>` | `./certs` | Directory holding `hub.crt`/`hub.key`/`ca.crt` (see [Generate lab test certificates](#generate-lab-test-certificates) above). |
| `--sc-hub-uri <wss://host:port/path>` | *(none)* | Also run the hub **connector** role: dial out to another hub at this URI. Off by default - this hub-only example needs only the listener role above for NM-SCH-B. |
| `--sc-failover-uri <wss://host:port/path>` | *(none)* | Optional failover hub URI, used only if `--sc-hub-uri` is also given. |
| `--sc-max-hub-connections <n>` | `4` | Max simultaneous inbound BACnet/SC peer connections the hub function accepts - enforced by the stack (see [Configuration file](#configuration-file) and `TODO.md`/this option's own doc comment in `main.cpp` for how). |
| `--dcc-password <string>` | *(none)* | Require this password on DeviceCommunicationControl/ReinitializeDevice requests (`common/` 2.6.0). |
| `--config <path>` | *(none)* | Read defaults for `device-id`, `port`, `sc-port`, `sc-cert-dir`, `sc-hub-uri`, `sc-failover-uri`, `dcc-password`, `sc-max-hub-connections` from a config file - see [Configuration file](#configuration-file) below. A matching CLI flag always overrides the config file. |
| `--help`, `-h` | - | Show usage (including the BACnet/SC options above) and exit. |
| `--version` | - | Print the example, stack, and `common/` helper versions, then exit. |

### Configuration file

`--config <path>` points at a small, dependency-free `key = value` text file
(no third-party INI/YAML/JSON library - see `config.h`) providing DEFAULTS for
`device-id`, `port`, `sc-port`, `sc-cert-dir`, `sc-hub-uri`, `sc-failover-uri`,
`dcc-password`, and `sc-max-hub-connections`. **Precedence is CLI args >
config file > this example's built-in defaults** - a flag given on the
command line always wins over the same key in the config file.

`example.conf` (checked in, at the repository root) is a commented template
with every key shown at its built-in default:

```ini
# example.conf
# device-id = 389022
# port = 47808
# sc-port = 47819
# sc-cert-dir = ./certs
# sc-hub-uri =
# sc-failover-uri =
# dcc-password =
# sc-max-hub-connections = 4
```

```bash
./build/BACnetExampleBSCHUB.exe --config example.conf
# a CLI flag still overrides the config file:
./build/BACnetExampleBSCHUB.exe --config example.conf --port 47876
```

Format rules: one `key = value` per line, `#` starts a comment to
end-of-line, blank lines are ignored, no `[sections]`. An unrecognised key or
an unparsable numeric value is logged as a warning and skipped - a malformed
config file never prevents the device from starting (an unopenable `--config`
*path*, however, is a startup error, since the user explicitly named it).

### Interactive commands

While the example runs, these keys are available:

| Key | Action |
|-----|--------|
| `h` | Show the version information and this command list. |
| `q` | Quit. |
| up arrow | Increase Analog Input 1 (`Bronze`) by 1.1. |
| down arrow | Decrease Analog Input 1 (`Bronze`) by 1.1. |

The up/down keys change the live `Present_Value` of the analog input, so a client
re-reading it sees the new value.

## Verify

### Over BACnet/IP (verified, real client)

Verified with a real BACnet client (not a hand check)
against a running instance of this example:

1. **Discover** - `who_is()` returns an **I-Am** from instance **389022**
   (vendor **389**).
2. **Read the Device** - ReadProperty `389022` `Object_Name` = `"Rainbow"`;
   `Vendor_Identifier` = `389`; `Model_Name` = `"CAS BACnet Stack Example -
   B-SCHUB"`.
3. **Read Analog Input 1** - `Present_Value` = `21.5`.
4. **Read Network Port 2** - `Object_Name` = `"BACnet SC"`; `Network_Type` =
   `11` (`secureConnect`) - confirming the BACnet/SC Network Port object is
   present and correctly typed, over ordinary BACnet/IP ReadProperty.
5. **Confirm the profile boundary** - a **WriteProperty** to any object is
   rejected, and `DeviceCommunicationControl` with the deprecated plain
   `disable` value is rejected with `service-request-denied`.

You can repeat this with the [CAS BACnet
Explorer](https://store.chipkin.com/products/tools/cas-bacnet-explorer).

### Over BACnet/SC (verified against a real peer)

Verified on the wire, against a real second process, not just against this
repository's own test scripts:

1. **Generate lab certificates** - `cmake --build build --target test-certs`
   (see [Generate lab test certificates](#generate-lab-test-certificates)
   above).
2. **Listener (hub-function accept role)** - `tests/sc/hub_listener_test.py`
   drives a hand-built BACnet/SC client against the running example and
   asserts: TLS 1.3 negotiates; the `hub.bsc.bacnet.org` subprotocol is
   echoed; a client with no certificate, TLS 1.2, or the wrong subprotocol is
   all refused/rejected; a text WebSocket frame is closed with code 1003; and
   a hand-built BVLC-SC Connect-Request gets a real Connect-Accept back:
   ```bash
   python -m pip install -r tests/sc/requirements.txt
   ./build/BACnetExampleBSCHUB.exe --sc-port 47819 --sc-cert-dir ./certs &
   python tests/sc/hub_listener_test.py --port 47819 --cert-dir certs
   ```
   Then, independently, a **real** BACnet/SC node
   (`BACnetSCCli.exe`, `Role=node`) completed Who-Is -> I-Am -> ReadProperty
   discovery of this device (`Object_Name` = `"Rainbow"`) over the SC
   connection.
3. **Connector (hub/node initiate role, `--sc-hub-uri`)** -
   `tests/sc/fake_hub_server.py` (a hand-built mutual-TLS fake hub) answers
   the example's Connect-Request with a Connect-Accept and the example's own
   console shows the hub-connector state machine reach `Connected`; killing
   the fake hub produces a `Disconnected` log line, with the **stack** (not
   this example's transport code) doing the later re-dial, per its own retry
   timer. Independently, against a **real** hub (`BACnetSCCli.exe`,
   `Role=hub`), the example's hub-connector state machine reaches
   `ConnectedPrimary`.
4. **Certificate File objects** - `tests/sc/file_object_test.py` (a real
   `bacpypes3` BACnet/IP client) confirms `AtomicReadFile(File 1, "Operational Certificate")`
   returns `certs/hub.crt` byte-for-byte, Network Port 2's
   `Issuer_Certificate_Files` has exactly 2 entries, and none of the 4 File
   objects ever serve `certs/hub.key`.
5. **Mux fairness** - with an SC peer connection held open, BACnet/IP
   Who-Is/I-Am keeps answering normally on port 47808 (or whatever `--port`
   is), confirming `ScTransportRouter`'s IP-first/SC-first alternating poll
   does not starve either datalink while both are busy.

See `tests/sc/README.md` for the full command lines and what each script
checks, and `sc_transport/README.md` for the transport's wire-level contract.

For a property-by-property review against the conformance statement, see
[TUTORIAL.md](TUTORIAL.md).

## Licence

The example source code (this repository, excluding `submodules/`) is
dedicated to the public domain under [CC0-1.0](LICENSE). Building this example
also links **third-party dependencies with their own licences**:
[libwebsockets](https://libwebsockets.org/) (MIT) and
[OpenSSL 3](https://www.openssl.org/) (Apache-2.0), both pulled in via vcpkg -
see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) for the full text/
pointers. The CAS BACnet Stack itself is a separate, commercially licensed
product (see [Requires the CAS BACnet Stack](#requires-the-cas-bacnet-stack-licensed-product)
above) and is not covered by any of the above.


## The BACnet profile example series

<!-- PROFILE-TABLE:BEGIN (generated from cas-bacnet-stack-examples/docs/profile-table.md - do not edit here) -->
The CAS BACnet Stack supports every standardized device profile in ASHRAE 135-2024 Annex L, and there is one example repository per profile. Pick the profile your device claims, then the language you build in. "Ask" means the example hasn't been built yet for that language - [contact Chipkin](https://store.chipkin.com/contact-us) if you need one.

### Controllers (Annex L.4)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-SS** Smart Sensor | [B-SS-CPP](https://github.com/chipkin/BACnetProfileExample-B-SS-CPP) | [B-SS-Node](https://github.com/chipkin/BACnetProfileExample-B-SS-Node) | [B-SS-CS](https://github.com/chipkin/BACnetProfileExample-B-SS-CS) | [B-SS-Rust](https://github.com/chipkin/BACnetProfileExample-B-SS-Rust) | [B-SS-Python](https://github.com/chipkin/BACnetProfileExample-B-SS-Python) | [B-SS-Go](https://github.com/chipkin/BACnetProfileExample-B-SS-Go) |
| **B-SA** Smart Actuator | [B-SA-CPP](https://github.com/chipkin/BACnetProfileExample-B-SA-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-ASC** Application Specific Controller | [B-ASC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ASC-CPP) | [B-ASC-Node](https://github.com/chipkin/BACnetProfileExample-B-ASC-Node) | Ask | Ask | Ask | Ask |
| **B-AAC** Advanced Application Controller | [B-AAC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AAC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-BC** Building Controller | [B-BC-CPP](https://github.com/chipkin/BACnetProfileExample-B-BC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Life safety controllers (Annex L.5)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-LSC** Life Safety Controller | [B-LSC-CPP](https://github.com/chipkin/BACnetProfileExample-B-LSC-CPP) 🚧 | Ask | Ask | Ask | Ask | Ask |
| **B-ALSC** Advanced Life Safety Controller | [B-ALSC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ALSC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Access control controllers (Annex L.6)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-ACC** Access Control Controller | [B-ACC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-AACC** Advanced Access Control Controller | [B-AACC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AACC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Lighting controllers (Annex L.11)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-LD** Lighting Device | [B-LD-CPP](https://github.com/chipkin/BACnetProfileExample-B-LD-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-LS** Lighting Supervisor | [B-LS-CPP](https://github.com/chipkin/BACnetProfileExample-B-LS-CPP) | Ask | Ask | Ask | Ask | Ask |

### Elevator controllers (Annex L.13)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-EM** Elevator Monitor | [B-EM-CPP](https://github.com/chipkin/BACnetProfileExample-B-EM-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-EC** Elevator Controller | [B-EC-CPP](https://github.com/chipkin/BACnetProfileExample-B-EC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-AEC** Advanced Elevator Controller | [B-AEC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AEC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Authentication and authorization (Annex L.14)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-AS** Authorization Server | [B-AS-CPP](https://github.com/chipkin/BACnetProfileExample-B-AS-CPP) | Ask | Ask | Ask | Ask | Ask |

### Miscellaneous (Annex L.7, combinable with any one family)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-BBMD** Broadcast Management Device | [B-BBMD-CPP](https://github.com/chipkin/BACnetProfileExample-B-BBMD-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-ACDC** Access Control Door Controller | [B-ACDC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACDC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-ACCR** Access Control Credential Reader | [B-ACCR-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACCR-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-RTR** Router | [B-RTR-CPP](https://github.com/chipkin/BACnetProfileExample-B-RTR-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-GW** Gateway | [B-GW-CPP](https://github.com/chipkin/BACnetProfileExample-B-GW-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-DAP** Device Address Proxy | [B-DAP-CPP](https://github.com/chipkin/BACnetProfileExample-B-DAP-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-SCHUB** BACnet/SC Hub | [B-SCHUB-CPP](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-GENERAL** General device (Annex L.8) | *(satisfied by every example above)* | — | — | — | — | — |

### Operator interfaces and workstations (Annex L.1–L.3, L.9–L.10, L.12)

Client-side profiles.

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-OD** Operator Display | [B-OD-CPP](https://github.com/chipkin/BACnetProfileExample-B-OD-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-OWS** Operator Workstation | planned | — | — | — | — | — |
| **B-AWS** Advanced Operator Workstation | planned | — | — | — | — | — |
| **B-XAWS** Extended Advanced Operator Workstation | planned | — | — | — | — | — |
| **B-LSAP** Life Safety Annunciator Panel | planned | — | — | — | — | — |
| **B-LSWS** Life Safety Workstation | planned | — | — | — | — | — |
| **B-ALSWS** Advanced Life Safety Workstation | planned | — | — | — | — | — |
| **B-ACSD** Access Control Security Display | planned | — | — | — | — | — |
| **B-ACWS** Access Control Workstation | planned | — | — | — | — | — |
| **B-AACWS** Advanced Access Control Workstation | planned | — | — | — | — | — |
| **B-LOD** Lighting Operator Display | planned | — | — | — | — | — |
| **B-ALWS** Advanced Lighting Workstation | planned | — | — | — | — | — |
| **B-LCS** Lighting Control Station | planned | — | — | — | — | — |
| **B-ALCS** Advanced Lighting Control Station | planned | — | — | — | — | — |
| **B-ED** Elevator Display | planned | — | — | — | — | — |
| **B-EWS** Elevator Workstation | planned | — | — | — | — | — |
| **B-AEWS** Advanced Elevator Workstation | planned | — | — | — | — | — |

🚧 = in progress. "Ask" = not yet built for that language; contact Chipkin if you need it. Profile definitions: ANSI/ASHRAE 135-2024 Annex L. BIBB definitions: Annex K. Get the stack: <https://store.chipkin.com/services/stacks/bacnet-stack>.
<!-- PROFILE-TABLE:END -->

## References

- **ANSI/ASHRAE Standard 135** (BACnet) - the protocol standard. Object model
  (Clause 12), services (Clause 16), BACnet/SC (Annex AB), device profiles
  (Annex L). Purchase / preview via the [ASHRAE store](https://www.ashrae.org/technical-resources/standards-and-guidelines).
- **What is BACnet?** - Chipkin's introduction:
  <https://docs.chipkin.com/protocols/bacnet/>.
- **CAS BACnet Stack** - product page and documentation:
  <https://store.chipkin.com/services/stacks/bacnet-stack>.
- **CAS BACnet Stack BACnet/SC Manual** -
  `submodules/cas-bacnet-stack/docs/CAS BACnet Stack - BACnet SC Manual_v6.md`
  (private, part of the stack submodule).
- **CAS BACnet Explorer** - client for testing this device:
  <https://store.chipkin.com/products/tools/cas-bacnet-explorer>.
- **Shared helper used by this example** - [`common/README.md`](common/README.md).

See also [TUTORIAL.md](TUTORIAL.md), [docs/PICS.md](docs/PICS.md),
[CHANGELOG.md](CHANGELOG.md), [TODO.md](TODO.md), and [AGENTS.md](AGENTS.md).
