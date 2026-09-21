# Tutorial - extending and reviewing the B-SCHUB example

[README.md](README.md) says what this example *is*. This document is the *how*:
how to extend it into your own device, who serves which property, how to review
the result for conformance, what it takes to call `BACnetStack_Tick()` correctly
in a real product, and what goes wrong when you get it subtly right.

Read this once before you start changing `main.cpp`. The most expensive mistake
in this example is silent, and the section it lives in is
[Add a second object instance](#add-a-second-object-instance).

- [Extending the example](#extending-the-example)
- [What each object type needs you to serve](#what-each-object-type-needs-you-to-serve)
- [Who serves what: the application or the stack?](#who-serves-what-the-application-or-the-stack)
- [Calling BACnetStack_Tick() in a real product](#calling-bacnetstack_tick-in-a-real-product)
- [Reviewing your device](#reviewing-your-device)
- [Troubleshooting](#troubleshooting)

## Extending the example

The example is intentionally small so it's easy to change.

**Change a sensor's value or name** - edit the constants / callbacks in
`main.cpp` (e.g. the initial value of `g_analogInput1Value`, or the `"Bronze"`
string in `GetPropertyCharString`).

**Change the device identity before you ship** - vendor ID, vendor name, model
name, description, firmware revision, device name, the DeviceCommunicationControl
password and the BACnet/SC device UUID are all in the
`CHANGE ALL OF THIS BEFORE YOU SHIP` block at the top of `main.cpp`, with a
per-field note on each saying what to change it to. That block is the
authoritative checklist; it is in the source rather than here so it cannot be
skipped by someone who only reads the code.

**Require a password for DeviceCommunicationControl** - set `DCC_PASSWORD` in
`main.cpp` to a non-empty string; the `DeviceCommunicationControl` callback then
rejects a mismatch with `password-failure` instead of accepting any request.

### Implement the BACnet/SC transport for real

Both transport roles are real, compiled, and verified against real peers -
see [README.md "BACnet/SC support"](README.md#bacnetsc-support-read-this-first)
for what's implemented and `sc_transport/README.md` for the wire-level
contract. This section is the "how it works, and how to take it further" a
reader who wants to productionize the pattern needs - not a build-it-yourself
checklist.

#### How it works

`main.cpp` section **2c**'s four transport callbacks
(`CallbackInitiateWebsocket`, `CallbackDisconnectWebsocket`,
`CallbackSCStartListening`, `CallbackSCStopListening`) are thin forwards into
`sc_transport/ScTransport` - a libwebsockets + OpenSSL wrapper (fetched via
vcpkg, never vendored) that implements both BACnet/SC transport roles:

- **Listener** (hub-function accept role, `StartListening()`/
  `StopListening()`) - the role this hub-only example actually needs, and the
  one always on.
- **Connector** (hub/node initiate role, `Connect()`/`Disconnect()`) - off
  unless `--sc-hub-uri` is given (this hub-only example does not need one to
  answer a node's own requests), included so this example can also
  demonstrate NM-SCH-B's connector side.

`sc_transport/ScTransportRouter` is the stack&lt;-&gt;transport glue: it
registers the stack's `ReceiveMessageForPort`/`SendMessageForPort` callbacks
(the stack holds only ONE pointer per callback slot, so this must happen
*after* `CASExampleHelper::RegisterCommonCallbacks()`) and dispatches between
BACnet/IP (its own UDP socket) and BACnet/SC (`ScTransport`) by
`networkPortInstance`, alternating which one it polls first each tick so
neither starves the other.

Full wire-level detail - the subprotocol string, the accepted-peer
connection-string convention, the WebSocket status enum, the exact
`SendMessageForPort` return-value contract, the 1497-byte ingress ceiling -
lives in **[`sc_transport/README.md`](sc_transport/README.md)**; this section
does not repeat it.

#### Certificates: what this example does, and what a real deployment needs instead

`scripts/generate-test-certs.cmake` generates a throwaway **lab CA**, signs a
hub certificate and a test node certificate with it, and writes them under
`certs/` (gitignored). This is explicitly **lab testing only** - every doc
comment and README section touching it says so. Turning this into a real
deployment's certificate story needs, at minimum:

1. **A real CA**, not a self-signed one this script mints on your machine.
   BACnet/SC's trust model is: the hub and every node it accepts must chain to
   a CA both sides trust. In a real deployment that is either your
   organization's own internal CA (a private PKI most building-automation
   integrators already run for other purposes) or, for a hub reachable from
   the public Internet, a certificate from a CA your BACnet/SC nodes are
   configured to trust specifically for this purpose - **not** a public web
   CA a browser trusts by default, since that would let any certificate that
   CA ever issues (for any website) pass this hub's `ssl_ca_filepath` check
   unless you also scope the accepted CA bundle down to just your own
   BACnet/SC issuing CA.
2. **A certificate rotation strategy.** This example's `certs/hub.crt` is
   generated once and read fresh off disk on every `AtomicReadFile` request
   and by `ScTransport` at listen/connect time - so replacing the files
   under `--sc-cert-dir` and restarting the process (or, for a production
   implementation, re-reading them on a `BACnetStack_SetBACnetSCWebSocketStatus`-
   driven reconnect rather than requiring a restart) is enough to rotate.
   What this example does **not** implement: automatic renewal before
   expiry, a CSR-based rotation flow (see point 4 below - the CSR-generation
   callback has no call site in this stack build, so there is no hook to wire
   one up through the stack today), or alerting when a certificate is close
   to expiring. `scripts/generate-test-certs.cmake`'s lab CA is valid 10
   years and the hub/node leaf certs a shorter, script-defined period - check
   the script for the exact values before relying on them for anything but a
   lab.
3. **A hostname/identity policy decision.** `ScTransport::Connect()` passes
   `LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK` when dialing out - deliberately,
   not by oversight. BACnet/SC certificates identify *BACnet/SC devices*
   (via the UUID this example sets with `BACnetStack_SetBACnetSCUuid`), not
   DNS hostnames, so there is no meaningful hostname to check a peer's
   certificate against the way a browser checks a website's. The CA chain is
   still fully verified either way - what is skipped is *only* the
   hostname-matches-SAN step, which does not apply to this transport's trust
   model. If your deployment wants to bind a specific accepted peer identity
   more tightly than "signed by a trusted CA" (e.g. pin a specific peer
   UUID), that policy has to be layered on top of `ScTransport` today - the
   stack does not expose a UUID-in-SAN binding check, and (point 4) its own
   validate-certificate callback is never called.
4. **A working validate-certificate hook, if you need one.** This example
   registers `CallbackValidateBACnetSCOperationalCertificate` and
   `CallbackGenerateBACnetSCCertificateSigningRequest` (`main.cpp` section
   2d) for documentation/completeness, but **neither is ever called** by
   this pinned stack build - confirmed by reading the stack's own source, not
   assumed. See [`TODO.md`](TODO.md) for the stack-issue candidate and
   `sc_transport/README.md`'s certificate-policy section for exactly what
   security property this leaves you with (CA-chain validation only,
   performed by OpenSSL at the TLS layer - not this callback).

#### Extending the pattern

- Both directions are already **asynchronous** - `ScTransport::Service()`
  pumps libwebsockets non-blockingly and only queues results; the main loop
  drains those queues into `BACnetStack_SetBACnetSCWebSocketStatus` afterward,
  never from inside an lws callback (see [Calling BACnetStack_Tick() in a real
  product](#calling-bacnetstack_tick-in-a-real-product) below for why that
  matters).
- Every real connection/status transition is already reported back through
  `BACnetStack_SetBACnetSCWebSocketStatus(uri, status, errorCode)` -
  `sc_transport/ScTransportRouter::DrainStatusEvents()` is where that happens.
- `BACnetStack_SetBACnetSCCertificateFileObjects` plus the 4 File objects
  (`main.cpp` section 2d) are already configured and read-verified over
  AtomicReadFile.

### Add a second object instance

Read this whole recipe before starting — the last step is the one that is easy
to miss and the one BTL will fail you for.

> **Why there are several edits, not just "add the object" — and why skipping
> one is SILENT.** Most of the `GetProperty*` callbacks match on **both**
> object type *and* instance (`objectInstance == ANALOG_INPUT_INSTANCE`), so a
> new instance falls through every one of them. `GetPropertyBool` is the
> exception: it matches on type only, so `Out_Of_Service` works for a new
> instance for free.
>
> Here is the part that matters, and it is the opposite of what most people
> assume: falling through a callback does **not** reliably produce an
> error. The stack errors only for the few properties it refuses to invent —
> `Present_Value`, `Number_Of_States`, `Relinquish_Default`, `Local_Date`,
> `Local_Time`, and a Network Port's `APDU_Length`. For everything else it **silently substitutes a default**:
>
> | Property | If you forget to serve it | Loud? |
> |---|---|:--:|
> | `Present_Value` | Error (`read-access-denied`) | yes |
> | `Object_Name` | reads back as the string **`"undefined"`** | **no** |
> | `Units` | reads back as **`no-units` (95)** | **no** |
> | `Out_Of_Service` | served on type alone — works by accident | n/a |
>
> **Doesn't the `errorCode` out-parameter fix this?** Only if you use it, and
> only where it is right to. Each `GetProperty*` callback ends with a
> `uint32_t* errorCode` that the stack presets to `success` and reads only when
> you return `false`, so you *can* turn any decline into a chosen BACnet error.
> But ending every callback with `*errorCode = unknown-property` breaks the
> device: the stack's decline-and-fabricate path is what answers required
> properties an application is not expected to serve — the Device's
> `Max_APDU_Length_Accepted`, `APDU_Timeout` and `Number_Of_APDU_Retries` among
> them. Name an error on the catch-all and those start failing instead of
> answering. Set `errorCode` only where *this device* knows the read is wrong;
> `main.cpp` does it in exactly one place, `State_Text` with an out-of-range
> array index. The table above is still how the fall-through behaves, and the
> diff below is still what catches a missed step.
>
> It is worse than "wrong value": the object's `Property_List` **still advertises
> `Units` (117)**. So the object actively claims to have the property, and then
> answers with a default. Nothing on the wire says you forgot anything.
>
> So a half-added object does not look broken; it looks **healthy**. Add two of
> them and both report `Object_Name "undefined"` — duplicate object names inside
> one device, which is a spec violation and a hard BTL failure that every scan
> tool will render as a perfectly good object. **"It scanned OK" is exactly the
> failure mode, not evidence against it.**

```cpp
// 1) a new instance number (in section 1).
//    Naming: a second object of a type is "<Colour> 2" - so Analog Input 2 is
//    "Bronze 2", NOT a new colour. Each object TYPE owns one colour series-wide
//    (Network Port 2 in this example, "BACnet SC", already follows this rule).
static const uint32_t ANALOG_INPUT_2_INSTANCE = 2;   // "Bronze 2"
static float g_analogInput2Value = 23.1f;            // its live value

// 2) add the object (in main, next to the other BACnetStack_AddObject calls).
//    Check the return, like every other stack call in this file.
if (!BACnetStack_AddObject(g_deviceInstance, OBJECT_TYPE_ANALOG_INPUT, ANALOG_INPUT_2_INSTANCE)) {
    printf("Error: Failed to add Analog Input 2 (Bronze 2).\n");
    return 1;
}

// 3) serve its Present_Value + Object_Name:
//    GetPropertyReal:        AI/2 + Present_Value -> *value = g_analogInput2Value;
//    GetPropertyCharString:  AI/2 + Object_Name   -> "Bronze 2"

// 4) DO NOT SKIP: serve its Units, in GetPropertyEnumerated.
//    Units is a REQUIRED property of an Analog Input. The existing check reads
//    `objectInstance == ANALOG_INPUT_INSTANCE`, which is instance 1 - so without
//    this, reading Analog Input 2's Units returns an ERROR and the object is
//    NON-CONFORMANT. It will still appear in the Object_List and its
//    Present_Value will read back perfectly, so the device looks healthy right
//    up until BTL certification.
//    GetPropertyEnumerated:  AI/2 + Units -> *value = ENGINEERING_UNITS_DEGREES_CELSIUS;
```

Then re-run the README's Verify steps **against Analog Input 2**, not just Analog
Input 1 — read every required property and **diff it against Analog Input 1**.
Any property that comes back `"undefined"`, `no-units`, or `0` where object 1
returns something real is a step you missed. Because the failure is silent (see
the table above), this diff is the only thing that catches it.

## What each object type needs you to serve

The application must serve every REQUIRED property the stack does not generate.
It differs per type — this is the checklist, so you do not have to infer it:

| Object type | You must serve | Plus |
|---|---|---|
| Analog Input | `Present_Value` (Real), `Object_Name`, `Units` | — |
| Binary Input | `Present_Value` (Enumerated), `Object_Name` | `Polarity` |
| Multi-State Input | `Present_Value` (Unsigned), `Object_Name` | `Number_Of_States` |
| Network Port | `Object_Name`, `Network_Type`, `Protocol_Level`, `Changes_Pending` | — (`Network_Type`/`Protocol_Level` are set from `BACnetStack_AddNetworkPortObject()`'s arguments, not a `GetProperty*` callback) |

## Who serves what: the application or the stack?

The single most common question when reading this file is "who answers this
property?" For Analog Input 1, the whole picture:

| Property | Served by | How |
|---|---|---|
| `Object_Identifier` | **stack** | generated from the object you added |
| `Object_Type` | **stack** | generated |
| `Object_List` | **stack** | generated (Device object) |
| `Property_List` | **stack** | generated |
| `Status_Flags` | **stack** | generated |
| `Event_State` | **stack**, sort of | no intrinsic alarming here, so nothing serves it — it reads `normal` only because `normal` is the enumeration's zero value and the stack substitutes a datatype default. Correct by coincidence, not design. |
| `Out_Of_Service` | **you** | `GetPropertyBool` — matched on object **type only** |
| `Present_Value` | **you** | `GetPropertyReal` |
| `Object_Name` | **you** | `GetPropertyCharString` |
| `Units` | **you** | `GetPropertyEnumerated` |

Every object, not just this one, is in [docs/PICS.md](docs/PICS.md).

Going beyond reading (writable points, outputs, COV, alarms) means implementing a
richer profile.

## Calling BACnetStack_Tick() in a real product

The example calls `Tick()` in a tight loop with a 1 ms sleep. What the stack
actually requires:

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

## Reviewing your device

After you have changed anything, review it against the conformance statement
rather than against "it looked fine in the explorer":

1. Regenerate [docs/PICS.md](docs/PICS.md) after editing `docs/objects.json`
   (see [Keeping the PICS honest](#keeping-the-pics-honest) below). A ⚠ row is a
   required property nothing serves.
2. Read **every** property listed for **every** object with a BACnet client, and
   compare the value against the PICS. `"undefined"`, `no-units` and `0` are the
   three shapes a missed callback takes.
3. Diff a new object of a type against the existing one of that type. Anything
   that differs and shouldn't is a callback that matched on instance.
4. Confirm the services you do **not** implement are still rejected - for
   B-SCHUB, WriteProperty to any object, and the deprecated plain `disable`
   value (1) on DeviceCommunicationControl (`service-request-denied`).
5. For BACnet/SC specifically: confirm the SC configuration calls all return
   success at start-up and that the console prints the
   `CallbackSCStartListening` line once, then confirm the transport itself
   with `tests/sc/hub_listener_test.py` (listener) and, if you enabled it,
   `tests/sc/fake_hub_server.py` (connector) - see [README.md "Over
   BACnet/SC"](README.md#over-bacnetsc-verified-against-a-real-peer). Both
   transport roles are real in this example; an actual SC node/hub connecting
   is verifiable, and should be verified, not assumed from the configuration
   calls succeeding alone.

### Keeping the PICS honest

`docs/PICS.md` is partly generated. `docs/objects.json` describes each object and
who serves which property; the series tool regenerates the object tables from it
plus the stack's own `docs/property-profile-reference.md` at the pinned commit:

```bash
python tools/gen-objects-properties.py BACnetProfileExample-B-SCHUB-CPP            # rewrite
python tools/gen-objects-properties.py BACnetProfileExample-B-SCHUB-CPP --check    # fail if stale
```

(That tool lives in the example-series repository, not in this one. If you only
have this repository, edit the generated block by hand and keep it matching the
callbacks in `main.cpp`.)

When you add an object or a property to `main.cpp`, update `docs/objects.json`
in the same change and regenerate. The `app` list is what the callbacks serve;
`accepted` is for a required property you deliberately leave to the stack's
default, and each one needs a justification. Anything required, not in `app` and
not in `accepted`, comes out as a ⚠ row - that is a defect, not a feature.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| On start-up the app prints a wall of red `Error:` lines but the device works | **Expected — this is not your bug.** Two benign sources, both from the stack's own debug logging: (1) the device receives its **own** broadcast I-Am and logs a decode cascade (*"Services is not supported service=[0]"* … *"Failed to process the incoming NPDU"*) — any BACnet/IP device that listens for broadcasts hears itself; (2) a one-time *"UUID has not been set..."* notice can appear from the stack's own BACnet/SC datalink bring-up before `BACnetStack_SetBACnetSCUuid` runs. On a healthy start-up roughly half the output is these lines. |
| Console prints a line every time `BACnetStack_Tick()` runs about listening for WebSocket connections | Fixed by design: `CallbackSCStartListening` only logs **once** (a static `warned` flag), even though the stack retries it every `Tick()` while it keeps returning `false`. If you see it repeating, check you're running the version in this repo. |
| No BACnet/SC node ever connects | The transport is real now, so this is worth debugging rather than assuming. Check: does `certs/` exist (`cmake --build build --target test-certs` if not - the console prints this exact command when certs are missing)? Does the peer trust the SAME CA (`certs/ca.crt`) this hub was generated with? Is the peer using the `hub.bsc.bacnet.org` subprotocol and TLS 1.3? `tests/sc/hub_listener_test.py` isolates each of these. See [README.md "Over BACnet/SC"](README.md#over-bacnetsc-verified-against-a-real-peer) and `sc_transport/README.md`. |
| CMake error: *"CAS BACnet Stack adapter not found under: ..."* | Submodules not initialized. Run `git submodule update --init --recursive` (or pass `-D CAS_STACK_DIR=...`). |
| `CASBACnetStackDLL.h: No such file or directory` | Same - submodules not checked out. |
| Windows: *"No CMAKE_CXX_COMPILER could be found"* | Install Visual Studio with the "Desktop development with C++" workload, then re-run from a fresh terminal. |
| First build seems stuck for minutes | Normal - it's compiling ~600 stack files. Only the first build is slow. |
| App prints *"Failed to bind UDP port 47808"* | Another BACnet program is already using 47808. Stop it, or run with `--port <n>`. |
| DeviceCommunicationControl `disable` returns an error | Expected. The plain `disable` value is deprecated at Protocol_Revision >= 20; use `disable-initiation` instead. |
| Client sends Who-Is but sees no I-Am | Firewall is blocking UDP 47808, or the client and device are on different subnets (Who-Is is a broadcast). Allow the port; test on the same subnet first. |
| Replies show an unexpected device instance or vendor | Another BACnet device is already answering on this host/port. On Linux/macOS two processes can share the port and both reply; on Windows the example asks for `SO_EXCLUSIVEADDRUSE` (`common/SimpleUDP.cpp`) so this shows up as a bind failure instead. Stop the other device, or use `--port`. |
