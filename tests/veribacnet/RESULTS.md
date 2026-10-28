# VeriBACnet results

The last run of this project (the 93 selected tests): VeriBACnet 0.20.0 against example v1.8.0 started
with `--port 47848`, over the BACnet/IP port (`external`, unaided, model-described).
Nothing here was run over BACnet/SC: VeriBACnet has no BACnet/SC transport yet.

| | Tests |
|---|---:|
| Selected for B-SCHUB | 93 |
| Passed | 37 |
| Failed | 0 |
| Errors | 0 |
| Skipped | 56 |

## What the 36 passes cover

The hub's own device over BACnet/IP: ReadProperty and ReadPropertyMultiple of
the Device, Analog Input, File and Network Port objects (every listed property
reads, the EPICS matches each `Property_List`), the Network Port `APDU_Length`,
dynamic device binding (Who-Is/I-Am) and dynamic object binding (Who-Has/I-Have,
local and remote-network, with and without a device range), and
DeviceCommunicationControl.

## Why 56 tests were skipped

| Count | Why |
|---:|---|
| 29 | The BACnet/SC hub function tests (clause 12.5) and one Network Port Command row that needs a BACnet/SC connection: the test tool cannot connect to the hub's `wss://` port yet, so they wait for an operator. **The hub function itself is not measured by this project.** |
| 12 | Network Port tests that need a modeled Network Port scenario (activate changes, discard changes, command failures): this hub has no writable network configuration to model. |
| 4 | Changing the Device's `Object_Name` / `Object_Identifier` over the network: they are set at start-up (`--device-name`, `--deviceID`), so the test needs an operator. |
| 4 | Disable-initiation tests that need the device to send something unprompted: a hub sends nothing until it is asked. |
| 4 | Database_Revision tests that need object creation, deletion or a changeable `Object_Name`: the hub has none. |
| 3 | DeviceCommunicationControl rows for Protocol_Revision 19 and earlier; this device is revision 30. |

## What is not measured, and where it is covered

- The BACnet/SC hub function, the hub connector and the BACnet/SC certificate
  procedures: `tests/sc/` covers them (see its README).
- 14 of the profile's required tests have no script in the test tool yet.

## Time synchronization (DM-TS-B and DM-UTC-B)

The example executes TimeSynchronization and UTCTimeSynchronization and keeps a
settable clock (`Local_Date`, `Local_Time`, with `UTC_Offset` and
`Daylight_Savings_Status`), which meets the NM-SCH-B option group "at least one
time synchronization method": the option group is not reported as unmet. Declaring
DM-UTC-B selects one more test, 7.3.2.10.8 (`UTC_Offset` is configurable: written
to -1440, -780, 0, +780, +1440 and two more values, each read back), which passes -
that is the 37th pass.

The test tool does not add the base tests of the two time synchronization BIBBs for
those options, so they were run by hand against the same example, each with
`run --project ... --id <test id>`, and all four passed: 9.30.1.1 and 9.30.1.2
(TimeSynchronization local broadcast / directed to the IUT) and 9.31.1.1 and
9.31.1.2 (the same for UTCTimeSynchronization: the local date and time are the
request's UTC converted with `UTC_Offset` and `Daylight_Savings_Status`). They are
not part of the 93 selected tests.
