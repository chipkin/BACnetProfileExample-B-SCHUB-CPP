# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
