# TODO

Known gaps in this example. Each line says what is missing and why.

## Testing

- **The relay between two connected BACnet/SC devices is not a CI test.** The
  CI tests use one connected device at a time. The relay was checked by hand at
  v1.7.1 (Who-Is and ReadProperty from one Python BACnet/SC device to another,
  through the hub).
- **The hub connector is tested against a fake hub, not a second real hub.**
  `tests/sc/connector_test.py` runs `tests/sc/fake_hub_server.py`; a run against
  a second instance of this example, or a production hub, is a manual check.
- **BACnet/IP (`--port`) is tested for discovery and addressing, not
  segmentation.** `ip_port_test.py` covers Who-Is/I-Am, `Object_List` and
  Network Port 1's addressing; segmentation is tested over BACnet/SC
  (`segmentation_test.py`), where the same stack code runs.
- **VeriBACnet (the BTL conformance tool) has no BACnet/SC transport yet**
  (tracker: chipkin/chipkin-bacnet-testing-tool#713), so `tests/veribacnet/`
  can only measure the hub's BACnet/IP side (`--port 47848`). The hub function
  itself (clause 12.5 hub rows of 135.1) is covered only by `tests/sc/`.
- **VeriBACnet does not select the DM-TS-B and DM-UTC-B base tests for this example.**
  The hub executes both time synchronization services (the NM-SCH-B "at least one time
  synchronization method" option), but the test tool's `tests select` only ticks the
  option and leaves out 9.30.1.1, 9.30.1.2, 9.31.1.1 and 9.31.1.2; they pass when run by hand
  (`tests/veribacnet/RESULTS.md`). Tracker: chipkin/chipkin-bacnet-testing-tool#744.
- **Daylight saving is not followed automatically.** `UTC_Offset` and
  `Daylight_Savings_Status` start from the host's time zone and are state; a
  transition needs a write of `Daylight_Savings_Status`. A device with a time-zone
  database would derive it from the clock.

## Features

- Longer names than 128 bytes, or non-ASCII names, in `--device-name`: on
  Windows the command line reaches the program in the system code page, so a
  name with accented letters is refused as not UTF-8. Use an ASCII name.
- Not part of this example (it is cut down to the B-SCHUB profile; see the
  production Chipkin BACnet SC Hub): an HTTP status page and certificate
  set-up portal, a configuration file, running as a service with installers, a
  TLS key log, certificate signing by the example itself, and the user manual.
