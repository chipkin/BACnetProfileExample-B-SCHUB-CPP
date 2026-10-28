# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.8.0] - 2026-10-27

Built on CAS BACnet Stack 6.x (`69b6249f`), Protocol_Revision 30, vendored
`common/` 3.5.0.

This release keeps what 1.6.0 and 1.7.x cut the example down to - BACnet/SC only
by default, at most 4 BACnet/SC devices, a 24-hour run limit, the demo
certificates, the certificate request at start-up, `--import-cari` and the log
file - and adds back the options a hub in a larger network needs. The hub still
starts exactly as before when none of them is given.

### Added

- **An optional BACnet/IP port**: `--port <n>` opens a UDP socket on `n` and adds
  Network Port 1 "BACnet IP", so the hub can also be found and managed over
  plain BACnet/IP (Who-Is/I-Am, ReadProperty, ReadPropertyMultiple), and
  broadcasts an I-Am when it starts. **Without `--port`
  the hub is BACnet/SC-only, as in 1.7.x: no UDP socket and no Network Port 1.**
  The hub function does not relay between BACnet/IP and BACnet/SC.
- **A hub connector with a failover hub**: `--sc-hub-uri <wss://...>` makes the
  hub also connect, as a node, to another BACnet/SC hub with its own certificate
  (mutual TLS 1.3); `--sc-failover-uri` is the hub it connects to when the
  primary can't be reached. `--sc-accept-hub-without-hello` accepts a
  Connect-Accept without the Hello option, from a hub that leaves it out (off by
  default; deviates from ANSI/ASHRAE 135 AB.2.2, and the hub says so). An
  `issuer-crl.pem` that holds no certificate revocation list makes the hub
  connect to no hub until it is fixed.
- **`--sc-rate-limit` and `--sc-rate-limit-total`**: how many new BACnet/SC
  connection attempts the hub accepts a second from one address (default 10) and
  in total (default 50); 0 turns a limit off. A refused attempt is cut off before
  the TLS handshake and logged, at most once every 10 seconds.
- **`--sc-max-hub-connections <n>`** lowers the limit of 4 BACnet/SC devices (1 to
  4). The limit can't be raised: a larger value is refused.
- **`--device-name`** sets the Device's `Object_Name` (1 to 128 bytes of UTF-8;
  ASCII on Windows), which must be unique on the BACnet internetwork. It is also
  the name in the hub's certificate request.
- **`--ip-network-number` and `--sc-network-number`** give the Network Ports a
  BACnet network number (reported as configured; the device is not a router).
- Self-tests under `tests/sc/`: `ip_port_test.py`, `hub_options_test.py` and
  `connector_test.py` (with `fake_hub_server.py`, a fake hub), run by the release
  workflow. `tests/veribacnet/` is a VeriBACnet project for Chipkin's BTL
  conformance tool, run over the BACnet/IP port.
- **TimeSynchronization (DM-TS-B)**: the hub executes the TimeSynchronization
  service and sets its clock; the Device now serves `Local_Date` and `Local_Time`
  (the host's local time with the correction the last synchronization applied).
  A request with an unspecified field or a day the month does not have is
  ignored. This is the "at least one time synchronization method" the NM-SCH-B
  options of the BTL Test Plan ask for. New self-test `tests/sc/time_sync_test.py`
  (over BACnet/IP and BACnet/SC), run by the release workflow.
- **UTCTimeSynchronization (DM-UTC-B)**: the hub also executes the
  UTCTimeSynchronization service. The Device serves `UTC_Offset` (minutes, west of
  Greenwich positive) and `Daylight_Savings_Status`, which start from the host's
  time zone (0 and FALSE when it cannot be determined) and are writable (any
  multiple of 15 minutes from -1440 to +1440 for `UTC_Offset`); `Local_Date` and
  `Local_Time` are the UTC minus `UTC_Offset`, plus an hour while daylight saving
  applies, and both time synchronization services move that clock. New self-test
  `tests/sc/utc_time_sync_test.py`, run by the release workflow.
- `TODO.md` lists the known gaps.

### Changed

- CAS BACnet Stack updated to `6.x` @ `69b6249f`; vendored `common/` updated to
  3.5.0.
- Every option is checked at start-up: a bad number, a missing value, a URI that
  isn't `wss://` or a network number used twice is refused instead of ignored.
- The release workflow is read-only by default (only the publishing job may
  write), takes the branch name from the environment instead of pasting it into
  a script, builds with a bounded parallelism so a Linux runner doesn't run out
  of memory, waits for the real ready line in the smoke test, cancels a pull
  request's earlier run when it is pushed again, and skips the build for a
  documentation-only pull request.

### Fixed

- **`Archive` of the File objects was not writable.** ANSI/ASHRAE 135-2024 clause
  12.13 makes it writable (conformance code W), but a WriteProperty to it was
  refused with write-access-denied. A client can now set it on Files 1 to 4; the
  hub only stores the flag.
- **Changes_Pending was TRUE on a hub that had just started.** The stack leaves
  the hub's own start-up binding of the certificate files pending, so Network
  Port 2 read `Changes_Pending` TRUE before anything had been written. The hub
  now activates its start-up configuration; a fresh hub reports FALSE.

## [1.7.1] - 2026-10-16

Verified against CAS BACnet Stack 6.0.23 (`6.x` @ `64b2cfac5`), Protocol_Revision
30, vendored `common/` 3.4.0.

### Changed

- **Stack Pin moved to `6.x` @ `64b2cfac5`** from `e6de4ffd`, per the series
  rule that a pin moves to the latest `6.x` on any update. No source change was
  needed. Every CI test step passes at the new pin on Windows and Linux, as it
  did at the old one (no regression).
- **`common/` 3.0.0 -> 3.3.0**, copied verbatim from B-SS-CPP `b640a81`
  (additive keys; a broadcast with no connection string is sent - this example
  has no BACnet/IP socket, so neither change is reachable here).
- **`common/` 3.3.0 -> 3.4.0**, copied verbatim from B-SS-CPP `5d78299`:
  `HelperSendMessage` sends a broadcast addressed to the socket's own address to
  the subnet broadcast instead. Not reachable here either (no BACnet/IP socket).
  All 14 BACnet/SC CI test steps pass on Windows and Linux, as before. No
  `wiretest/`: the tests here are `tests/sc/` with their own BACnet/SC client.
- README and PICS now say what the tests prove about the hub function: the CI
  tests use one connected BACnet/SC device at a time, so the relay between two
  connected devices is not a CI test. It was checked by hand at this version
  with two Python BACnet/SC devices (Who-Is from one reached the other and its
  I-Am came back; a ReadProperty between them was answered).

### Added

- **`tests/sc/discovery_test.py`**: the series' discovery Wire Test, over
  BACnet/SC (this example has no BACnet/IP port). Who-Is through the hub, the
  Device's `Object_List` (control: exactly Device 389022, Analog Input 1, File
  1-4, Network Port 2), then every object's `Property_List` and a raw
  ReadProperty of every listed property; any Error, Reject, Abort or silence
  fails it. 116 reads, all values, on Windows and Linux. CI runs it after the
  segmentation test.

## [1.7.0] - 2026-10-07

Verified against CAS BACnet Stack 6.0.23 (`6.x` @ `e6de4ffd`), Protocol_Revision
30, vendored `common/` 3.0.0 (unchanged).

### Removed

- **BACnet/IP** ([#1](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/1)).
  Network Port 1 "BACnet IP" and its UDP socket are gone, and so is `--port`:
  the device is reachable only over BACnet/SC, through its hub function. The
  BACnet/SC Network Port keeps instance 2 (the CARI tree's `port-2`, so
  existing certificate sets keep working). No I-Am is sent at start-up (no
  device is connected yet); devices find the hub with Who-Is through the hub.
- **`--generate-csr`** ([#2](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/2)) -
  the certificate request is now made at start-up (below).

### Added

- **The certificate request at start-up** ([#2](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/2)).
  If `<sc-cert-dir>/hub-cari-request.zip` doesn't exist, the hub makes it; an
  existing one is never overwritten. One start-up line says it was created or
  already exists, with its full path. An existing private key is never
  replaced: the request is made from the CSR on disk, and only a hub with no
  key at all gets a new key and CSR. `--help` describes the file.
- **The log file `logs/B-SCHUB.log`** ([#3](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/3)),
  in the folder the example runs in: a copy of everything shown on the
  console, including the CAS BACnet Stack's and libwebsockets' output, emptied
  at each start-up, so it can be sent to support. Its full path is printed at
  start-up.
- **`--help` links to this repository** ([#4](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/4)),
  <https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP>, and names the
  files the example writes.
- **The example stops after 24 hours** ([#5](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/5))
  (`DEMO_RUN_LIMIT_SECONDS`), exit code 0, saying why; restart it to continue.
  For automated tests only, the environment variable
  `BSCHUB_TEST_RUN_LIMIT_SECONDS` shortens the limit (it can't raise it) - not
  a command-line option.
- Tests: `startup_test.py` (`--help`, the log file, no BACnet/IP),
  `run_limit_test.py`, and `sc_client.py` - a BACnet client over BACnet/SC
  (bacpypes3 on a hub connection). `file_object_test.py`, `rpm_test.py`,
  `segmentation_test.py` and `cert_procedure_test.py` now run over BACnet/SC
  with the same checks; `rpm_test.py` also checks `Object_List` has one
  Network Port and `Protocol_Revision` is 30.

### Changed

- The product is named only at start-up and on limit errors - the start-up
  banner, the connection-limit warning and the run-limit stop - each ending
  "For a production-ready BACnet/SC hub, the Chipkin BACnet SC Hub: Contact
  Chipkin sales@chipkin.com". `--help` no longer prints the banner.
- Before the BACnet/SC listener closes (the stack stops it on ReinitializeDevice
  `ACTIVATE_CHANGES`, or certificates are reloaded), frames already queued are
  sent first (up to 500 ms), so the device that asked - itself connected over
  BACnet/SC - gets its acknowledgement.

## [1.6.0] - 2026-10-07

Verified against CAS BACnet Stack 6.0.23 (`6.x` @ `e6de4ffd`), Protocol_Revision
30, vendored `common/` 3.0.0.

This release cuts the example down to what the **B-SCHUB profile** requires.
It is an example of using the CAS BACnet Stack to build a BACnet/SC hub, for
evaluation and testing only. A production BACnet/SC hub is the **Chipkin
BACnet SC Hub** - contact sales@chipkin.com.

The history of earlier versions is not carried in this repository.

### Kept

- The B-SCHUB device: Device 389022 "Chipkin Example B-SCHUB", Analog Input 1,
  Network Ports 1 (BACnet/IP) and 2 (BACnet/SC), and the four certificate File
  objects.
- ReadProperty, ReadPropertyMultiple (segmented in both directions),
  Who-Is/I-Am, Who-Has/I-Have, DeviceCommunicationControl.
- The BACnet/SC hub function (NM-SCH-B) on its own WebSocket/TLS transport
  (TLS 1.3, mutual authentication), with a built-in connection-attempt rate
  limit and certificate revocation lists (`issuer-crl.pem`).
- The clause 19.8.3 certificate procedures over BACnet: WriteProperty
  `File_Size`, AtomicWriteFile, ReinitializeDevice `ACTIVATE_CHANGES`, and
  Network Port `Command` `DISCARD_CHANGES` / `GENERATE_CSR_FILE`.
- `--sc-accept-device-without-hello` for YABE.
- The console keys: `h`, `q`, up/down, and `m` (BACnet/SC counters).

### Changed

- **Certificates are CARI files from a Certificate Authority.** The example
  no longer signs certificates or makes a CA. It reads the hub's CARI tree
  (ANSI/ASHRAE 135-2024 Annex AA.2) from `--sc-cert-dir`, makes its own key
  and certificate request with `--generate-csr` (`hub-cari-request.zip`), and
  installs a CA's CARI response (such as one from BACnet International's
  BACCARI) with `--import-cari <zip>`.
- **A demo certificate set is included** in `certs/` (made with
  `tools/make_test_certs.py`), so the example runs out of the box. Its private
  keys, including the CA's, are public - for testing on an isolated network
  only.
- **At most 4 BACnet/SC devices**, fixed. A 5th is refused by the stack, and
  the example logs a warning (at most once a minute).
- The start-up banner says this is an example, for evaluation and testing
  only, and where to get a production hub.
- The command line is `--sc-cert-dir`, `--port`, `--sc-port`,
  `--sc-accept-device-without-hello`, `--generate-csr`, `--import-cari`,
  `--help` and `--version`; anything else is refused as an unknown option.
- DeviceCommunicationControl and ReinitializeDevice take no password.
- The release is a signed Windows `.zip` and a Linux `.tar.gz` (the
  executable, `certs/`, README, licence, third-party notices and PICS), with
  `SHA256SUMS.txt`.

### Removed

These are production conveniences of the Chipkin BACnet SC Hub, not part of
the profile:

- The HTTP server: status page, `/health`, `/metrics`, certificate upload and
  the `/setup` certificate guide (`--http-*`).
- Running as a service (`--service`, `--install-service`,
  `--uninstall-service`), the installers and the `.deb` package.
- The configuration file (`--config`) and the log file (`--log-file`).
- The hub connector and failover (`--sc-hub-uri`, `--sc-failover-uri`,
  `--sc-accept-hub-without-hello`).
- `--sc-max-hub-connections`, `--sc-rate-limit`, `--sc-rate-limit-total`.
- `--device-name`, `--ip-network-number`,
  `--sc-network-number`, `--bacnet-ip off`.
- The TLS key log (`--sc-keylog-file`), `--inspect`, `--migrate-certs` and
  older certificate-folder layouts.
- Certificate signing and the built-in lab CA (`--generate-certs` and
  related options).
- The user manual, fact sheet, production-certificates guide, support policy,
  BTL test plan, their PDFs, and the SBOM tool.
