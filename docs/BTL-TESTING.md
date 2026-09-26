# BTL testing

This page is the plan and the record for testing the hub against the BACnet
Testing Laboratories (BTL) test plan for the **B-SCHUB** profile, and for
BACnet/SC interoperability testing. It sits next to the
[PICS](PICS.md) ([PDF](PICS.pdf)), which states what the device claims.

**Status: not yet tested by BTL or at a plugfest.** The results tables below
are empty until a test run is recorded. The example's own automated checks
(`tests/sc/`, run in CI) are listed at the end; they are not a substitute for
the BTL test plan.

## Decision: BTL listing

To be decided by Chipkin. This example is limited to 4 BACnet/SC connections
and is meant for evaluation, so a listing would normally be for a product
built from it rather than for the example itself. Running the test plan
against the example still shows where the code stands before a product
inherits it.

## What to test

The BIBBs the PICS claims, with the BTL test plan section for each:

| BIBB | What the device does | BTL test plan area |
|---|---|---|
| DS-RP-B | Executes ReadProperty | Data Sharing - ReadProperty-B |
| DS-RPM-B | Executes ReadPropertyMultiple | Data Sharing - ReadPropertyMultiple-B |
| DM-DDB-B | Answers Who-Is with I-Am, sends I-Am at start-up | Device Management - Dynamic Device Binding-B |
| DM-DOB-B | Answers Who-Has with I-Have | Device Management - Dynamic Object Binding-B |
| DM-DCC-B | Executes DeviceCommunicationControl | Device Management - DeviceCommunicationControl-B |
| NM-SCH-B | BACnet/SC hub function | Network Management - BACnet/SC Hub-B |

Also covered by the test plan for any device:

- Clause 13 - basic device and object tests: every required property of every
  object (Device, Analog Input, Network Port 1 and 2, File 1-4), read-only
  properties refuse writes, `Protocol_Revision` 30, `Object_List`.
- The Network Port object tests for both ports, including the BACnet/SC
  properties of Network Port 2.
- Certificate management over BACnet (clause 19.8.3): WriteProperty
  `File_Size`, AtomicWriteFile and ReinitializeDevice `ACTIVATE_CHANGES` /
  `WARMSTART` on the certificate File objects.

BACnet/SC interoperability, at a BACnet International plugfest or with the BTL
BACnet/SC test tools:

- nodes from other vendors connect to the hub (TLS 1.3, mutual
  authentication, `hub.bsc.bacnet.org`), exchange unicast and broadcast
  traffic through it, and survive a hub restart;
- the hub connector (`--sc-hub-uri`) connects to other vendors' hubs,
  including failover;
- certificate procedures driven by other vendors' tools.

## Known deviations to check first

These are known and documented; record how the test plan treats each one:

- The Network Port `Command` property isn't exposed on Network Port 2, so
  `GENERATE_CSR_FILE`
  ([#10](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/10))
  and `DISCARD_CHANGES`
  ([#29](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/29))
  can't be written; both wait on CAS BACnet Stack changes.
- Network Port 2 reads `Changes_Pending` TRUE right after start-up with
  nothing written (cas-bacnet-stack#2866,
  [#41](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/41)).
- A device's Connect-Request without the Hello option is refused (strict
  AB.2.2) unless `--sc-accept-device-without-hello` is on; test with both
  compatibility settings off.
- At most 4 BACnet/SC connections (an evaluation limit of this example).

## Results

Record each run here: date, version (`--version` output), test plan
revision, tool and tester.

### Run: _not yet run_

| Test | Result | Notes / deviation |
|---|---|---|
| | | |

### Interoperability: _not yet run_

| Peer (vendor, product, version) | Role | Result | Notes |
|---|---|---|---|
| | | | |

## The example's own checks

Run on Windows and Linux for every pull request (`.github/workflows/release.yml`,
[tests/sc/README.md](../tests/sc/README.md)):

- `hub_listener_test.py` - TLS 1.3, subprotocol, refusal of bad clients,
  Connect-Request/Connect-Accept (also with `--bacnet-ip off`).
- `file_object_test.py` - the certificate File objects over BACnet/IP.
- `cert_procedure_test.py` - the clause 19.8.3 procedures.
- `rpm_test.py` - ReadPropertyMultiple.
- `http_test.py` - status page, `/health`, `/metrics`, certificate upload.
- `fake_hub_server.py` - the hub connector.
