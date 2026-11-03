# VeriBACnet Project

This folder is the **VeriBACnet Project** for the BACnet B-SCHUB (BACnet
Secure Connect Hub) C++ example. VeriBACnet is Chipkin's BACnet conformance
tool; it runs the BTL test plan (ANSI/ASHRAE 135.1) against a running BACnet
device. The files here describe this example the way VeriBACnet's desktop app
saves a project: which device to test, what that device is, and which tests
apply to it.

Nothing in here is needed to build or run the example itself.

## How to run it

The project tests the hub over its **BACnet/IP port**, which is opt-in. Start
the example from the repository folder (so it finds `./certs`) with `--port 47848`
and `--sc-port 47924` (the project's target is `127.0.0.1`, UDP port 47848, device
instance 389022; the EPICS declares the hub's accept URI `wss://0.0.0.0:47924/`),
then run VeriBACnet against the project:

```
./build/BACnetExampleBSCHUB --port 47848 --sc-port 47924     # Linux
.\build\Release\BACnetExampleBSCHUB.exe --port 47848 --sc-port 47924     # Windows

veribacnet run --project tests/veribacnet/b-schub-cpp.project.json
```

`veribacnet tests select --project tests/veribacnet/b-schub-cpp.project.json`
re-chooses the tests (113 at the time of writing) and `veribacnet run ... --dry-run`
shows what would run without sending anything.

## What this project can and cannot measure

The hub function (NM-SCH-B) exists only on the hub's **BACnet/SC port**: TLS 1.3
WebSockets with mutual certificate authentication. The current VeriBACnet
release has no BACnet/SC transport, so it cannot connect to that port. A run
therefore measures the hub's own device over BACnet/IP (the objects, the
properties, discovery, DeviceCommunicationControl) and nothing about the hub
function. The hub rows of the BTL test plan (clause 12.5, 27 rows) are in the
test list, but they cannot reach the hub; the example's own scripts in
`tests/sc/` cover the BACnet/SC side meanwhile.

What the project format cannot say yet, and so is not in these files:

- the hub's `wss://` URI (the project's target is an address, a UDP port and a
  device instance);
- the test device's client certificate and key, and the issuer certificate the
  hub trusts;
- which BACnet/SC role the test device plays (a node on the hub, a failover
  hub, a direct connection).

`RESULTS.md` in this folder says what the last run measured.

## What is in the project

| File | What it is |
|---|---|
| `b-schub-cpp.project.json` | The project: its name and id, the device to test (address 127.0.0.1, UDP port 47848, device instance 389022), the profile (B-SCHUB), and the list of selected tests. It names the description and the snapshot. |
| `b-schub-cpp.iut-description.json` | What the tests expect the device to be: its identity strings, the services and object types it supports, its segmentation and maximum APDU size, its eight objects (in the device's own `Object_List` order), the BIBBs it claims and the Test Plan options it declares. Written from this example's `docs/PICS.md`, `docs/objects.json` and `main.cpp`, and checked against a capture of the running device. |
| `b-schub-cpp.device-model.json` | The desktop app's view of the same device: the claimed BIBBs, the EPICS header (profile, product description, both data links), and the test settings. |
| `b-schub-cpp.device-snapshot.json` | A capture of the running example (`veribacnet device capture --stable-name`), with the host-specific values left out. `tests select` uses it to tick the options the device shows. |
| `b-schub-cpp.tpi` | The EPICS (the device's capabilities statement), written from `docs/PICS.md`. Values that change at run time are `?`. |

## The tests

`veribacnet tests select --profile B-SCHUB` chose the tests saved in the
project (113 at the time of writing): ReadProperty, dynamic device and object
binding, DeviceCommunicationControl, the Network Port object, and the
BACnet/SC hub tests of ANSI/ASHRAE 135.1 clause 12.5. The example executes
TimeSynchronization (DM-TS-B) and UTCTimeSynchronization (DM-UTC-B), either of which
is the "at least one time synchronization method" the NM-SCH-B options ask for; the
project declares the options `9.9::Supports DM-TS-B` and `9.9::Supports DM-UTC-B`.
The test tool does not add the four base tests for them (9.30.1.1, 9.30.1.2, 9.31.1.1
and 9.31.1.2) to the saved list; they are run with
`veribacnet run --project ... --id btl-1351-9-30-1-1` (and the other three ids) - see RESULTS.md.
