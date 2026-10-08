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
name, device name and the BACnet/SC device UUID are all in the
`CHANGE ALL OF THIS BEFORE YOU SHIP` block at the top of `main.cpp`, with a
per-field note on each saying what to change it to. A real product also makes
`Object_Name` configurable per unit, as the device instance already is
(`--deviceID`, default 389022, the series' instance for this example).

**Require a password for DeviceCommunicationControl and ReinitializeDevice** -
the example accepts any request. A real device compares the `password`
argument of both callbacks with its own secret and answers
`ERROR_CODE_PASSWORD_FAILURE` on a mismatch. Keep the secret out of the command
line (it would show in process listings).

**Check the BACnet/SC side without a BACnet client** - press `m` for the
connection and traffic counters `ScTransport` keeps (devices connected,
connects, refusals, rate-limit rejections, RX/TX).

**The connection limit** - `SC_MAX_HUB_CONNECTIONS` (4) is passed to
`BACnetStack_SetBACnetSCHubFunctionConfig`. The CAS BACnet Stack enforces it at
the BACnet/SC protocol layer: the WebSocket/TLS connection in
`sc_transport/ScTransport` still completes, and it is the BVLC-SC
Connect-Request immediately afterwards that the stack refuses with a NAK. The
main loop notices the refusal in `ScTransport::GetMetrics()` and logs why.

**The run limit** - the main loop stops the example after
`DEMO_RUN_LIMIT_SECONDS` (24 hours), logging why (`RUN_LIMIT_MESSAGE_FORMAT`).
The product is named in only three messages: the start-up banner and the two
limit messages (connection limit, run limit) - `PRODUCT_CONTACT` in
`main.cpp`. A test shortens the limit with the environment variable
`BSCHUB_TEST_RUN_LIMIT_SECONDS` (it can't raise it), not a command-line option.

**The log file** - `log_file.cpp` copies everything written to the console to
`logs/B-SCHUB.log` (emptied at each start-up). It points the process's stdout
and stderr at a pipe and copies the pipe to the console and the file from a
background thread, so it catches every line - `printf`,
`CASExampleHelper::Log`, libwebsockets and the CAS BACnet Stack itself -
without touching any of them, or `common/`.

**The certificate request at start-up** - `CertTool::EnsureHubRequest()`
(`cert_tool.cpp`) makes `<sc-cert-dir>/hub-cari-request.zip` if it doesn't
exist and never overwrites it. It never replaces a private key: with a key it
uses the CSR already on disk, and only a hub with no key at all (no
`key-hub.pem`, no pending key) gets a new key and CSR.

**Read multiple properties in one request** - this example enables
ReadPropertyMultiple (DS-RPM-B) alongside ReadProperty. No extra callback is
needed on the application side: the stack resolves each requested property
through the same path ReadProperty uses.

### How the BACnet/SC transport works

The transport is real, compiled, and verified against real peers;
`sc_transport/README.md` is the wire-level contract.

`main.cpp` section **2c**'s transport callbacks (`CallbackSCStartListening`,
`CallbackSCStopListening`, `CallbackDisconnectWebsocket`) are thin forwards
into `sc_transport/ScTransport` - a libwebsockets + OpenSSL wrapper (fetched
via vcpkg, never vendored) that implements the hub function's **listener**:
TLS 1.3, mutual authentication, the `hub.bsc.bacnet.org` subprotocol. A hub
does not dial out, so the example registers no `CallbackInitiateWebsocket`.

`sc_transport/ScTransportRouter` is the stack&lt;-&gt;transport glue: it
registers the stack's `ReceiveMessageForPort`/`SendMessageForPort` callbacks
(the stack holds only ONE pointer per callback slot, so this must happen
*after* `CASExampleHelper::RegisterCommonCallbacks()`) and moves the BACnet/SC
Network Port's messages to and from `ScTransport`.

**There is no BACnet/IP port.** BACnet/SC is the device's only data link, so
the hub's own device - its objects, the certificate procedures, Who-Is - is
reached through the hub function: a device connects to the hub, finds the
hub's device with Who-Is, and sends its requests to the VMAC the I-Am came
from. `tests/sc/sc_client.py` does exactly that (a bacpypes3 application on a
hub connection). The BACnet/SC Network Port keeps instance 2, because the CARI
certificate tree names the port (`cert1/device-<n>/port-2/`). One consequence:
a ReinitializeDevice `ACTIVATE_CHANGES` arrives over the very connection the
listener restart drops, so `ScTransport` sends what is queued (the
acknowledgement) before it closes connections (`kFlushBeforeClose`).

#### Certificates: what this example does, and what a real deployment needs

The example reads a **CARI** tree (ANSI/ASHRAE 135-2024 Annex AA.2) from
`--sc-cert-dir` (`cert_layout.cpp`). It never signs a certificate: it makes its
own request at start-up (and its key, if it has none - `cert_tool.cpp`), and
installs a CA's CARI response (`--import-cari`). The demo set in `certs/` came from
`tools/make_test_certs.py`, a throwaway test CA whose keys are public. A real
deployment needs, at minimum:

1. **A real CA** - the Chipkin BACnet SC Certificate Authority, BACnet
   International's BACCARI, or your organization's own. BACnet/SC's trust
   model is: the hub and every device it accepts must chain to a CA both sides
   trust. **Not** a public web CA a browser trusts by default - that would let
   any certificate it ever issued pass the hub's CA check.
2. **A certificate rotation strategy.** A client can replace the hub's
   certificate and add a second issuer over BACnet (clause 19.8.3); the hub
   validates the new set (`CertStore::ValidateStaged()`) and restarts its
   listener without restarting the process. Key-pair regeneration is there
   too: a client writes `GENERATE_CSR_FILE` to Network Port 2's `Command`, and
   `CertStore::GenerateKeyAndCsr()` makes a new key (kept pending until a
   certificate for it is activated) and CSR. What the example does **not**
   do: renew automatically, or alert before a certificate expires (it only
   logs a warning at start-up).
3. **A hostname/identity policy decision.** BACnet/SC certificates identify
   *devices* (the UUID set with `BACnetStack_SetBACnetSCUuid`), not DNS
   names. The example checks the CA chain and the CRL; binding a specific
   peer identity more tightly has to be layered on top of `ScTransport`.
4. **Certificate validation is yours, not the stack's.** The stack has no TLS
   path and no certificate-validation callback. Its one certificate hook is
   the Network Port Command callback, which asks the application to make a
   new key and CSR on `GENERATE_CSR_FILE`. All validation happens in
   `ScTransport`'s TLS context, via OpenSSL.

#### Extending the pattern

- Both directions are already **asynchronous** - `ScTransport::Service()`
  pumps libwebsockets non-blockingly and only queues results; the main loop
  drains those queues into `BACnetStack_SetBACnetSCWebSocketStatus` afterward,
  never from inside an lws callback (see [Calling BACnetStack_Tick() in a real
  product](#calling-bacnetstack_tick-in-a-real-product) below for why that
  matters).
- Every connection/status transition is reported back through
  `BACnetStack_SetBACnetSCWebSocketStatus` -
  `sc_transport/ScTransportRouter::DrainStatusEvents()` is where that happens.
- `BACnetStack_SetBACnetSCCertificateFileObjects` plus the 4 File objects
  (`main.cpp` section 2d) expose the certificates over BACnet.

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
> `main.cpp` never needs to: none of its objects has an array property the
> application serves. The table above is still how the fall-through behaves, and the
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

Then re-run AGENTS.md's "How to verify a change" steps **against Analog Input 2**, not just Analog
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
| Network Port | `Object_Name`, `Network_Type`, `Protocol_Level`, `Changes_Pending` | — (`Network_Type`/`Protocol_Level` are set from `BACnetStack_AddNetworkPortObject()`'s arguments, not a `GetProperty*` callback) |
| File | `Object_Name`, `File_Type`, `File_Size`, `Modification_Date`, `Archive`, `Read_Only` | AtomicReadFile (`CallbackReadFile`) |

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
  callbacks - `CallbackSCStartListening` must start the listener without
  waiting, and connection status is reported later through
  `BACnetStack_SetBACnetSCWebSocketStatus`, exactly as the doc comments say.

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
   B-SCHUB, WriteProperty to anything but a certificate File object's
   `File_Size` or a Network Port's `Command`, and the deprecated plain
   `disable` value (1) on DeviceCommunicationControl (`service-request-denied`).
5. For BACnet/SC specifically: confirm the SC configuration calls all return
   success at start-up and that the console prints the "listening" line once,
   then confirm the transport itself with `tests/sc/hub_listener_test.py` and
   `tests/sc/connection_limit_test.py` - see [README.md "Testing"](README.md#testing).
   An actual SC device connecting is verifiable, and should be verified, not
   assumed from the configuration calls succeeding alone.

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
| On start-up the app prints red `Error:` lines but the device works | **Expected — this is not your bug.** A one-time *"UUID has not been set..."* notice can appear from the stack's own BACnet/SC datalink bring-up before `BACnetStack_SetBACnetSCUuid` runs. |
| No BACnet/SC device ever connects | Check: is the hub listening (the "listening for WebSocket/TLS connections" line; the start-up "cert diagnostics" lines say what is wrong with the certificates if not)? Was the device's certificate signed by a CA in `cert1/issuer/` (a refused certificate is logged with OpenSSL's reason)? Does the device trust the issuer of the hub's certificate? Is it using the `hub.bsc.bacnet.org` subprotocol and TLS 1.3 (YABE on Windows 10 can't)? Does it send the Hello option (YABE doesn't: use `--sc-accept-device-without-hello`)? Are 4 devices already connected? `tests/sc/hub_listener_test.py` isolates most of these; see `sc_transport/README.md`. |
| CMake error: *"CAS BACnet Stack adapter not found under: ..."* | Submodules not initialized. Run `git submodule update --init --recursive` (or pass `-D CAS_STACK_DIR=...`). |
| `CASBACnetStackDLL.h: No such file or directory` | Same - submodules not checked out. |
| Windows: *"No CMAKE_CXX_COMPILER could be found"* | Install Visual Studio with the "Desktop development with C++" workload, then re-run from a fresh terminal. |
| First build seems stuck for minutes | Normal - it's compiling ~600 stack files. Only the first build is slow. |
| A BACnet/IP tool can't find the hub | Expected: the example has no BACnet/IP port. Connect to the hub over BACnet/SC (`wss://<this computer>:4443/`) with a device certificate, and send Who-Is there. |
| *"could not create the log file"* | Another copy of the example is already running in the same folder (on Windows it holds `logs/B-SCHUB.log`), or the folder isn't writable. The example still runs, logging to the console only; run each copy from its own folder. |
| The example stopped after 24 hours | Expected: the run limit. Start it again; for a hub that keeps running, see the Chipkin BACnet SC Hub. |
| DeviceCommunicationControl `disable` returns an error | Expected. The plain `disable` value is deprecated at Protocol_Revision >= 20; use `disable-initiation` instead. |
| Client sends Who-Is but sees no I-Am | The client must be connected to the hub over BACnet/SC and send Who-Is through it (there is no BACnet/IP). Check the device's Connect-Request was accepted (the "SC audit" lines). |
