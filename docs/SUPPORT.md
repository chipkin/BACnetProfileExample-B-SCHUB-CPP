# Support and versioning policy

This page says which versions of the B-SCHUB example are supported, what a
version number promises, and how to get help.

## Versions

Releases use [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

| Change | Version bump | Example |
|---|---|---|
| Bug or security fix, no change to anything below | PATCH | 1.2.0 -> 1.2.1 |
| New feature, option, config key, HTTP field or endpoint; existing ones keep working | MINOR | 1.2.1 -> 1.3.0 |
| A breaking change (below) | MAJOR | 1.3.0 -> 2.0.0 |

### What counts as a breaking change

Anything that makes a working installation stop working after an update:

- removing or renaming a **command-line option** or **config-file key**, or
  changing what an existing value means;
- changing the **certificate file names** in `--sc-cert-dir` without still
  reading the old ones (older names such as `hub.crt` keep working);
- removing an **HTTP endpoint** or a field of `/health` or `/metrics`, or
  changing a field's meaning (new fields may be added at any time);
- changing the **BACnet objects** a client relies on: object types and
  instances, `Object_Name` defaults, the Network Port layout, or the services
  the device executes (see [PICS.md](PICS.md));
- changing a **default** that affects what reaches the network, such as a
  port number or making a listener bind beyond loopback.

A behaviour change that closes a security hole may ship in a MINOR or PATCH
release if waiting would leave installations exposed; the release notes and
[CHANGELOG.md](../CHANGELOG.md) say so clearly, with what to change.

Every release's notes list what changed. Anything deprecated keeps working for
at least one MINOR release, with a warning in the log, before a MAJOR release
removes it.

## Supported versions

- The **latest release** gets bug fixes and security fixes.
- When a new MAJOR version is released, the last release of the previous
  MAJOR version gets **security fixes for 6 months**.
- Older releases aren't supported. Update to the latest release; the
  changelog lists anything to change.

The CAS BACnet Stack version each release is built with is printed by
`--version` and listed in the release's software bill of materials
(`sbom.cdx.json`), together with the OpenSSL, libwebsockets and other
library versions.

## Security fixes

How to report a vulnerability, and how fast we respond, is in
[SECURITY.md](../SECURITY.md). Security fixes are released as a new PATCH
release with a GitHub security advisory, and the release notes say which
issue they fix.

## Getting help

- **Questions, bugs and feature requests:** open a
  [GitHub issue](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues).
  Include `BACnetExampleBSCHUB --version`, your platform, the relevant log
  lines and, for connection problems, the `SC audit:` and `SC TLS` lines.
- **Commercial support, a production BACnet/SC hub (more than 4
  connections), or a CAS BACnet Stack licence:** contact Chipkin at
  **support@chipkin.com**.

This example is for evaluation and testing (at most 4 BACnet/SC connections).
Support for it is best effort; production support comes with a commercial
agreement.
