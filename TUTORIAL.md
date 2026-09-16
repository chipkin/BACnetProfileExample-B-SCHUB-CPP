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

This is the biggest gap in this example, and it is documented, not hidden - see
[README.md "BACnet/SC support"](README.md#bacnetsc-support-read-this-first) for
the full finding. `main.cpp` section **2c** registers four transport callbacks
(`CallbackInitiateWebsocket`, `CallbackDisconnectWebsocket`,
`CallbackSCStartListening`, `CallbackSCStopListening`) that are honest stubs:
they log exactly what the stack asked for and decline, rather than claiming a
connection that does not exist. To turn this into a working BACnet/SC hub, see
[`TODO.md`](TODO.md) for the exact list, which comes down to:

1. A dependency-free WebSocket **listener** (RFC 6455 framing over a TCP
   socket) for `CallbackSCStartListening` - the role this hub-only example
   actually needs. `common/SimpleUDP.cpp` is the existing pattern for a
   minimal platform socket wrapper to build it on.
2. A TLS 1.2+ layer underneath it - BACnet/SC's accept URIs are required to use
   the `wss://` scheme, so this is not optional for a conformant hub. Every
   practical option vendors a crypto library (OpenSSL, mbedTLS, BoringSSL,
   wolfSSL, or a platform TLS API), which is why it was not attempted in this
   spike - see `TODO.md` for the full reasoning.
3. Both directions must be **asynchronous** - never block inside a callback
   (see [Calling BACnetStack_Tick() in a real product](#calling-bacnetstack_tick-in-a-real-product)
   below).
4. Every real connection/status transition reported back through
   `BACnetStack_SetBACnetSCWebSocketStatus(uri, status, errorCode)`.
5. A certificate story: `BACnetStack_SetBACnetSCCertificateFileObjects` plus
   `RegisterCallbackValidateBACnetSCOperationalCertificate` and
   `RegisterCallbackGenerateBACnetSCCertificateSigningRequest` - none of which
   this example configures.

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
//    (Network Port 2 in this example, "Vermilion 2", already follows this rule).
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
   `CallbackSCStartListening` line once. An actual SC node connecting is
   **not** verifiable without a real transport implementation - do not claim
   it works without one.

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
| No BACnet/SC node ever connects | Expected - the WebSocket/TLS transport is a documented stub in this build. See [README.md "BACnet/SC support"](README.md#bacnetsc-support-read-this-first) and [`TODO.md`](TODO.md). |
| CMake error: *"CAS BACnet Stack adapter not found under: ..."* | Submodules not initialized. Run `git submodule update --init --recursive` (or pass `-D CAS_STACK_DIR=...`). |
| `CASBACnetStackDLL.h: No such file or directory` | Same - submodules not checked out. |
| Windows: *"No CMAKE_CXX_COMPILER could be found"* | Install Visual Studio with the "Desktop development with C++" workload, then re-run from a fresh terminal. |
| First build seems stuck for minutes | Normal - it's compiling ~600 stack files. Only the first build is slow. |
| App prints *"Failed to bind UDP port 47808"* | Another BACnet program is already using 47808. Stop it, or run with `--port <n>`. |
| DeviceCommunicationControl `disable` returns an error | Expected. The plain `disable` value is deprecated at Protocol_Revision >= 20; use `disable-initiation` instead. |
| Client sends Who-Is but sees no I-Am | Firewall is blocking UDP 47808, or the client and device are on different subnets (Who-Is is a broadcast). Allow the port; test on the same subnet first. |
| Replies show an unexpected device instance or vendor | Another BACnet device is already answering on this host/port. On Linux/macOS two processes can share the port and both reply; on Windows the example asks for `SO_EXCLUSIVEADDRUSE` (`common/SimpleUDP.cpp`) so this shows up as a bind failure instead. Stop the other device, or use `--port`. |
