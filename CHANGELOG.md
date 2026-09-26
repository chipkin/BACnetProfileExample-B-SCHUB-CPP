# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Open work is tracked in
[GitHub issues](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues).

## [1.4.0] - unreleased

### Added

- `--sc-accept-device-without-hello` (config: `sc-accept-device-without-hello`),
  off by default: the hub accepts a device whose Connect-Request omits the
  Hello destination option, such as YABE (issue #40). Uses the CAS BACnet
  Stack's new compatibility flag 0x02 (cas-bacnet-stack#3097); it combines with
  `--sc-accept-hub-without-hello` (0x01). The hub logs a warning at start-up
  while it is on.

## [1.3.0] - 2026-09-26

### Added

- `--generate-certs` / `--add-client-certs` also write, in each client
  folder, the files Windows tools such as YABE need: `<label>.pfx`
  (certificate, key and issuer; empty password, private), the issuer as
  `issuer-certificate.cer` (DER), and a ready-to-select YABE BACnet/SC
  channel file, `yabe-bacnetsc.config`
  ([#38](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/38)).
- The Windows installer is code-signed like the program, and every release
  download (the Linux archive and `.deb` included) has a signed
  build-provenance attestation: `gh attestation verify <file> --repo
  chipkin/BACnetProfileExample-B-SCHUB-CPP`
  ([#34](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/34)).
- On Windows 10 the hub logs a start-up warning: BACnet/SC tools on that
  computer that use Windows' own TLS (such as YABE) can't connect, because
  Windows 10 can't make the TLS 1.3 client connections BACnet/SC requires
  ([#39](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/39)).
- The Windows executable is code-signed, and each release includes
  `SHA256SUMS.txt`
  ([#34](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/34)).
- Installers and service support: a Windows installer that sets up the
  **BACnetSCHub** Windows service (`--install-service`/`--uninstall-service`,
  start on boot, restart on failure), a Debian/Ubuntu `.deb` and a Linux
  archive with `install.sh` that set up the **bacnet-schub-hub** systemd
  unit, and clean shutdown on SIGTERM/SIGINT
  ([#34](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/34)).
- `SECURITY.md` (how to report a vulnerability, response times, supported
  versions), `docs/SUPPORT.md` (support and versioning policy: what counts as
  a breaking change), and `docs/BTL-TESTING.md` (BTL test plan and results
  record). Each release includes a CycloneDX software bill of materials,
  `sbom-windows.cdx.json` and `sbom-linux.cdx.json` (`tools/make-sbom.py`).
  `THIRD-PARTY-NOTICES.md` now also covers libuv, zlib and pthreads4w, which
  vcpkg links in for libwebsockets
  ([#32](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/32)).
- A production certificate guide, `docs/production-certificates.md`: site or
  enterprise CA, signing the hub's CSR, rotation, changing the CA,
  revocation, certificate contents and key protection
  ([#18](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/18)).
- HTTPS for the status page and HTTP endpoints: `--http-tls` (config
  `http-tls`), using the hub's own certificate or `--http-tls-cert` /
  `--http-tls-key`. The off-loopback warning now only appears over plain HTTP
  ([#22](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/22)).
- `POST /certs/<slot>` is rate-limited: at most 5 attempts a minute from one
  address and 30 in total, then HTTP 429 and a log line, so the upload token
  can't be guessed at network speed
  ([#24](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/24)).
- Certificate revocation: put CRLs in `issuer-crl.pem` in `--sc-cert-dir` and
  the hub refuses devices whose certificates are revoked (it also checks the
  hub it connects out to). A new or changed file is picked up within 5 seconds
  without a restart; devices reconnect and revoked ones are refused. Checking
  fails closed. The status page shows whether a CRL is installed
  ([#15](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/15)).
- `--device-name` (config `device-name`) sets the Device's `Object_Name`, so
  each hub can have the unique name BACnet requires
  ([#33](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/33)).
- `--ip-network-number` / `--sc-network-number` (config `ip-network-number`,
  `sc-network-number`) set each Network Port's `Network_Number`, reported
  with quality `configured`
  ([#33](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/33)).
- Log files with rotation: `--log-file` (config `log-file`) also writes all
  console output to a file, rotated at `--log-max-size-mb` (default 10) with
  `--log-max-files` (default 5) old files kept
  ([#33](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/33)).
- CI keeps vcpkg's OpenSSL/libwebsockets builds in a GitHub Packages NuGet
  feed as well as the 7-day `actions/cache`, so a cold dependency build is no
  longer the usual case
  ([#17](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/17)).
- CI runs every `tests/sc/` script on Windows and Linux, including the new
  `http_test.py` (status page, `/health`, `/metrics`, upload auth,
  validation and rate limit), the connector against `fake_hub_server.py`,
  and `rpm_test.py`
  ([#33](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/33)).
- BACnet/SC-only mode: `--bacnet-ip off` (config `bacnet-ip = off`) opens no
  UDP port and leaves out Network Port 1, so the device is reachable only over
  BACnet/SC. The hub warns if BACnet/SC then isn't listening; `/health` and the
  status page show the mode
  ([#35](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/35)).
- The connection audit trail names the BACnet/SC device, not only the
  socket: the certificate subject it presented, and its VMAC and device UUID
  once the hub accepts it (or refuses it). The status page lists the connected
  devices the same way
  ([#21](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/21)).
- `--sc-accept-hub-without-hello` (config: `sc-accept-hub-without-hello`), off
  by default: lets the hub connector work with a hub that omits the Hello
  option from its Connect-Accept. It deviates from ANSI/ASHRAE 135 and doesn't
  change what the hub accepts from devices
  ([#19](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/19)).

### Changed

- When the hub refuses a BACnet/SC Connect-Request, the audit log gives the
  CAS BACnet Stack's own reason (from the BVLC-Result NAK it sends, e.g.
  "Connect messages require the Hello destination option") instead of
  guessing; `hub_listener_test.py` checks a Connect-Request without Hello
  gets that NAK
  ([#40](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/40)).
- `cert_procedure_test.py` checks `Changes_Pending` is FALSE after
  ACTIVATE_CHANGES, and reports the start-up `Changes_Pending` = TRUE stack
  bug as a known issue; the manual documents it
  ([#41](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/41)).
- `POST /certs/<slot>` validates an upload the same way as a certificate
  written over BACnet - a real X.509 parse, and the hub certificate must still
  match its key and chain to an issuer - before anything reaches disk, then
  reloads BACnet/SC with it straight away. A bad upload gets HTTP 400 with the
  reason; a `csr` upload must be a request for the hub's own key
  ([#25](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/25)).
- `POST /certs/<slot>` has its own secret, `http-upload-token` (config file
  only), instead of reusing `dcc-password`: set it to use the upload endpoint,
  which stays disabled until you do. Both secrets are compared in constant
  time, and the hub warns if they are the same
  ([#23](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/23)).
- BACnet/SC connection attempts are rate-limited per source address:
  `--sc-rate-limit` (default 10 a second) now applies to each address on its
  own, so one flooding host can't starve devices reconnecting from other
  addresses. The new `--sc-rate-limit-total` (default 50 a second) limits the
  whole listener. Refusals are logged with the source address
  ([#20](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/20)).
- The user manual is `docs/manual.md` (and `manual.pdf`), with installation,
  service set-up and firewall sections, and there is a two-page fact sheet
  (`docs/fact-sheet.md`, `fact-sheet.pdf`); both ship with every release.
  The README is a short landing page again. `docs/build-pdfs.py` (was
  `build-pics-pdf.py`) builds all three PDFs
  ([#30](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/30)).

### Fixed

- A BACnet/SC device that stops reading can no longer make the hub buffer
  without limit: after 64 frames are waiting for it, the hub closes its
  connection (close code 1008) and logs it. `/metrics` counts these closes
  (`sc_tx_queue_overflows`)
  ([#16](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/16)).
- Closing a BACnet/SC connection from the hub (the stack dropping a
  duplicate device, or a certificate reload closing the hub connector) now
  actually closes the socket; before, it only set the close reason.
- A client that asks for an unknown WebSocket subprotocol (a typo, say) gets
  an HTTP 400 response naming the subprotocol the hub accepts, instead of a
  dropped connection
  ([#27](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/27)).
- The BACnet/SC listener recovers from a start-up failure (the port briefly
  in use, a certificate that doesn't load yet) by retrying every 5 seconds,
  instead of needing a restart
  ([#28](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/28)).

## [1.2.0] - not released

These changes were never tagged on their own; they ship in 1.3.0.

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

### Changed

- The example accepts at most 4 BACnet/SC devices at a time. It is for
  evaluation and testing; a higher `sc-max-hub-connections` stops the hub with
  an error. For a production hub, contact support@chipkin.com.
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
  includes a `bacnetsc.config` for the CAS BACnet Explorer.
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
