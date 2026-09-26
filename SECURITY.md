# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public GitHub issue:

- **GitHub:** use **Report a vulnerability** on this repository's
  [Security tab](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/security)
  (private vulnerability reporting), or
- **Email:** support@chipkin.com with "Security" in the subject.

Include the version (`BACnetExampleBSCHUB --version` prints the example,
CAS BACnet Stack and `common/` versions), the platform, what you did, what
happened, and how to reproduce it. A proof of concept helps; please don't test
against systems you don't own.

## What happens next

| Step | Target |
|---|---|
| We acknowledge your report | within 7 business days |
| We confirm whether it's a vulnerability, and its severity | within 10 business days |
| A fix or mitigation for a confirmed high or critical issue | within 30 days |
| A fix for a confirmed medium or low issue | in the next planned release |

We'll keep you informed, agree a disclosure date with you, and credit you in
the release notes unless you prefer not to be named. Fixes are published as a
new patch release on the
[Releases page](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases)
with a GitHub security advisory.

## Supported versions

Security fixes go into the latest release only (see
[docs/SUPPORT.md](docs/SUPPORT.md) for the support and versioning policy).
Update to the latest release to get them.

| Version | Security fixes |
|---|---|
| Latest 1.x release | Yes |
| Anything older | No - update to the latest release |

## Scope

In scope: this repository's code - the hub (`main.cpp`), the BACnet/SC
transport (`sc_transport/`), the certificate handling (`cert_store.cpp`,
`cert_tool.cpp`), the HTTP endpoints and the release packages.

Report problems in the CAS BACnet Stack itself to Chipkin the same way; they
are fixed in the stack and picked up here with a stack update. Problems in
OpenSSL, libwebsockets and the other third-party libraries (see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)) belong with those projects;
we update the versions this example is built with when they publish a fix.
Each release's software bill of materials (`sbom.cdx.json`) lists the exact
versions.

Known limitations that are by design - for example, the hub doesn't check a
peer's host name, because BACnet/SC certificates identify devices, not DNS
names - are listed in the [manual's "Security" section](docs/manual.md#9-security).
