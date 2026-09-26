# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Open work is tracked in
[GitHub issues](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues).

## [1.2.0] - unreleased

### Added

- Replace the hub's certificates over BACnet with the BACnet/SC certificate
  procedures (ANSI/ASHRAE 135 clause 19.8.3): write a new operational or
  issuer certificate, then activate it with ReinitializeDevice. The hub checks
  the new certificates before using them
  ([#10](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/10)).
- A second trusted issuer slot, so a site can move to a new CA gradually.
- Status page at `http://127.0.0.1:8080/` showing versions, health,
  BACnet/SC state and connection counts, with links to this project and the
  CAS BACnet Stack.
- `/health` reports whether the hub is working (HTTP 200 or 503); `/metrics`
  reports connection and traffic counters.
- Every BACnet object has a Description saying what it is for.
- PICS as a PDF (`docs/PICS.pdf`), included in the release packages.
- The Windows executable is code-signed, and each release includes
  `SHA256SUMS.txt`
  ([#34](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/34)).

### Changed

- The example accepts at most 4 BACnet/SC devices at a time. It is for
  evaluation and testing; a higher `sc-max-hub-connections` stops the hub with
  an error. For a production hub, contact sales@chipkin.com.
- The hub certificate from `--generate-certs` also names this computer's LAN
  address, so devices can connect by IP address
  ([#9](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/9)).
- The README is now the user manual.
- CAS BACnet Stack 6.0.23.

### Removed

- Binary Input 1 and Multi-state Input 1, which this profile doesn't need.

### Fixed

- The hub stays up when BACnet/SC restarts, for example after new
  certificates are activated
  ([#13](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/13)).
- Reading all Device properties at once (ReadPropertyMultiple ALL) works
  ([#9](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/9)).

## [1.1.18] - 2026-09-24

### Added

- BACnet/SC hub function: devices connect over TLS 1.3 WebSockets with mutual
  certificate authentication, and the hub relays their traffic.
- Optional hub connector (`--sc-hub-uri`, `--sc-failover-uri`) to join another
  BACnet/SC hub.
- Built-in lab certificate generator: `--generate-certs [n]` makes a CA, the
  hub's certificate and `n` labeled device certificates;
  `--add-client-certs [n]` adds more devices later. Each device folder
  includes a `bacnetsc.config` for the Chipkin BACnet Explorer.
- Certificate File objects: operational certificate, certificate signing
  request and issuer certificates, readable over BACnet.
- ReadPropertyMultiple (DS-RPM-B).
- Configuration file (`--config`), including a DeviceCommunicationControl
  password that is never passed on the command line.
- Settings for the maximum BACnet/SC connections and connection attempts per
  second.
- Health and metrics endpoints over HTTP, and an optional certificate upload
  endpoint.
- Connection, disconnection and refused-handshake logging, and a certificate
  check at start-up.

## [1.0.0] - 2026-09-15

### Added

- First release: a BACnet/IP device implementing the B-SCHUB device profile,
  with a BACnet/SC Network Port configured for the hub function.
