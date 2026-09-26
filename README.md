# BACnet/SC Hub (B-SCHUB) - C++ example

A BACnet Secure Connect (BACnet/SC) hub built on the
[CAS BACnet Stack](https://store.chipkin.com/services/stacks/bacnet-stack).
BACnet/SC devices connect to it over TLS 1.3 WebSockets and it relays their
BACnet traffic, the way a BACnet/IP broadcast domain does for UDP devices. A
BACnet/IP port keeps it visible to BACnet/IP tools (or can be turned off). It
implements the **B-SCHUB** device profile (ANSI/ASHRAE 135 Annex L) and is
both a working hub for evaluation and testing (up to 4 BACnet/SC connections)
and a starting point for your own product.

**[Download the latest release](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases)** -
a Windows installer, a Debian/Ubuntu package, a Linux archive, or the bare
program - or [build it yourself](#build). The Windows executable is
code-signed by Chipkin, and each release lists SHA-256 checksums in
`SHA256SUMS.txt` ([how to check](docs/code-signing.md#checking-a-release)).

## Quick start

```bash
BACnetExampleBSCHUB --generate-certs   # a lab CA, the hub's certificate and 3 device certificates
BACnetExampleBSCHUB                    # start the hub
```

Then open **<http://127.0.0.1:8080/>** for the status page, and give each
BACnet/SC device one `certs/clients/<label>/` folder (the
[CAS BACnet Explorer](https://store.chipkin.com/products/tools/cas-bacnet-explorer) imports its `bacnetsc.config`). The installers do the certificate
step for you and run the hub as a service.

## Documentation

| Document | For |
|---|---|
| **[User manual](docs/manual.md)** ([PDF](docs/manual.pdf)) | Installing, configuring and running the hub: every option and config key, certificates, connecting devices, certificate management over BACnet, the status page and HTTP endpoints, security, troubleshooting. |
| **[Fact sheet](docs/fact-sheet.md)** ([PDF](docs/fact-sheet.pdf)) | A two-page summary for evaluation: profile, BIBBs, data links, platforms, security. |
| **[PICS](docs/PICS.md)** ([PDF](docs/PICS.pdf)) | The Protocol Implementation Conformance Statement: every object, property and service. |
| **[Production certificates](docs/production-certificates.md)** | Using your own CA, rotation, revocation and key protection. |
| **[TUTORIAL.md](TUTORIAL.md)** | How the code works and how to build your own product from it. |
| **[CHANGELOG.md](CHANGELOG.md)** | What changed in each release. |

## Build

You need a CAS BACnet Stack licence to build (see [Licensing](#licensing)).

**Prerequisites:** a C++17 compiler, CMake 3.15+, Git and
[vcpkg](https://vcpkg.io/) with `VCPKG_ROOT` set (vcpkg supplies OpenSSL and
libwebsockets).

- Windows: Visual Studio with "Desktop development with C++" (it includes
  vcpkg; use a Developer Command Prompt) and CMake.
- Debian/Ubuntu: `sudo apt install build-essential cmake git ninja-build pkg-config`,
  plus vcpkg.
- macOS: `xcode-select --install`, `brew install cmake ninja`, plus vcpkg.

```bash
git clone --recursive https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP.git
cd BACnetProfileExample-B-SCHUB-CPP
cmake -B build -S .
cmake --build build --config Release
```

The program is `build/BACnetExampleBSCHUB` (Linux/macOS) or
`build\Release\BACnetExampleBSCHUB.exe` (Windows). Cloned without
`--recursive`? Run `git submodule update --init --recursive` first. The first
build compiles the CAS BACnet Stack (about 600 files) and, the first time on a
machine, OpenSSL (10-15 minutes); later builds are incremental. After
updating the stack submodule, run `cmake -B build` again before building. To
use a stack outside the submodule:
`cmake -B build -S . -D CAS_STACK_DIR=/path/to/cas-bacnet-stack`.

The PDFs are built from the Markdown with `python docs/build-pdfs.py` (needs
`pip install markdown` and Chrome or Edge).

## Testing

`tests/sc/` holds the verification scripts (Python 3,
`pip install -r tests/sc/requirements.txt`); see its
[README](tests/sc/README.md). CI runs all of them on Windows and Linux for
every pull request.

| Script | Checks |
|---|---|
| `hub_listener_test.py` | TLS 1.3 and subprotocol negotiation, refusal of bad clients, and a BACnet/SC Connect-Request/Accept. |
| `file_object_test.py` | The certificate File objects over BACnet/IP; the private key is never served. |
| `cert_procedure_test.py` | Certificate management over BACnet: add issuer, rejected activation, replace the hub certificate. |
| `fake_hub_server.py` | A test hub for the `--sc-hub-uri` connector. |
| `rpm_test.py` | ReadPropertyMultiple against the Device. |
| `cert_files_test.py` | The `.pfx`, `.cer` and YABE config `--generate-certs` writes for each device. |
| `http_test.py` | The status page, `/health`, `/metrics`, and certificate upload auth, validation and rate limiting. |

## Licensing

- **This project** (everything outside `submodules/`) is public domain under
  [CC0-1.0](LICENSE).
- **CAS BACnet Stack** - a commercial Chipkin product, included as a private
  git submodule. You need a licence to build this project, not to use a
  [prebuilt release](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases).
  Contact <https://store.chipkin.com/services/stacks/bacnet-stack> or
  support@chipkin.com.
- **libwebsockets** (MIT) and **OpenSSL 3** (Apache-2.0), via vcpkg, with
  libwebsockets' own dependencies libuv (MIT), zlib (Zlib) and, on Windows,
  pthreads4w (Apache-2.0). See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
  Each release includes a software bill of materials (`sbom-*.cdx.json`,
  CycloneDX) listing the exact versions.

## Support and security

- [docs/SUPPORT.md](docs/SUPPORT.md) - which versions are supported, what
  counts as a breaking change, and how to get help. For a production hub or
  commercial support, contact **support@chipkin.com**.
- [SECURITY.md](SECURITY.md) - how to report a vulnerability privately, and
  how fast we respond.
- [docs/BTL-TESTING.md](docs/BTL-TESTING.md) - the BTL test plan for this
  profile and the record of test runs.
- Open work is tracked as [GitHub issues](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues).

## The BACnet profile example series

<!-- PROFILE-TABLE:BEGIN (generated from cas-bacnet-stack-examples/docs/profile-table.md - do not edit here) -->
The CAS BACnet Stack supports every standardized device profile in ASHRAE 135-2024 Annex L, and there is one example repository per profile. Pick the profile your device claims, then the language you build in. "Ask" means the example hasn't been built yet for that language - [contact Chipkin](https://store.chipkin.com/contact-us) if you need one.

### Controllers (Annex L.4)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-SS** Smart Sensor | [B-SS-CPP](https://github.com/chipkin/BACnetProfileExample-B-SS-CPP) | [B-SS-Node](https://github.com/chipkin/BACnetProfileExample-B-SS-Node) | [B-SS-CS](https://github.com/chipkin/BACnetProfileExample-B-SS-CS) | [B-SS-Rust](https://github.com/chipkin/BACnetProfileExample-B-SS-Rust) | [B-SS-Python](https://github.com/chipkin/BACnetProfileExample-B-SS-Python) | [B-SS-Go](https://github.com/chipkin/BACnetProfileExample-B-SS-Go) |
| **B-SA** Smart Actuator | [B-SA-CPP](https://github.com/chipkin/BACnetProfileExample-B-SA-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-ASC** Application Specific Controller | [B-ASC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ASC-CPP) | [B-ASC-Node](https://github.com/chipkin/BACnetProfileExample-B-ASC-Node) | Ask | Ask | Ask | Ask |
| **B-AAC** Advanced Application Controller | [B-AAC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AAC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-BC** Building Controller | [B-BC-CPP](https://github.com/chipkin/BACnetProfileExample-B-BC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Life safety controllers (Annex L.5)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-LSC** Life Safety Controller | [B-LSC-CPP](https://github.com/chipkin/BACnetProfileExample-B-LSC-CPP) 🚧 | Ask | Ask | Ask | Ask | Ask |
| **B-ALSC** Advanced Life Safety Controller | [B-ALSC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ALSC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Access control controllers (Annex L.6)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-ACC** Access Control Controller | [B-ACC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-AACC** Advanced Access Control Controller | [B-AACC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AACC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Lighting controllers (Annex L.11)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-LD** Lighting Device | [B-LD-CPP](https://github.com/chipkin/BACnetProfileExample-B-LD-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-LS** Lighting Supervisor | [B-LS-CPP](https://github.com/chipkin/BACnetProfileExample-B-LS-CPP) | Ask | Ask | Ask | Ask | Ask |

### Elevator controllers (Annex L.13)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-EM** Elevator Monitor | [B-EM-CPP](https://github.com/chipkin/BACnetProfileExample-B-EM-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-EC** Elevator Controller | [B-EC-CPP](https://github.com/chipkin/BACnetProfileExample-B-EC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-AEC** Advanced Elevator Controller | [B-AEC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AEC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Authentication and authorization (Annex L.14)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-AS** Authorization Server | [B-AS-CPP](https://github.com/chipkin/BACnetProfileExample-B-AS-CPP) | Ask | Ask | Ask | Ask | Ask |

### Miscellaneous (Annex L.7, combinable with any one family)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-BBMD** Broadcast Management Device | [B-BBMD-CPP](https://github.com/chipkin/BACnetProfileExample-B-BBMD-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-ACDC** Access Control Door Controller | [B-ACDC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACDC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-ACCR** Access Control Credential Reader | [B-ACCR-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACCR-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-RTR** Router | [B-RTR-CPP](https://github.com/chipkin/BACnetProfileExample-B-RTR-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-GW** Gateway | [B-GW-CPP](https://github.com/chipkin/BACnetProfileExample-B-GW-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-DAP** Device Address Proxy | [B-DAP-CPP](https://github.com/chipkin/BACnetProfileExample-B-DAP-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-SCHUB** BACnet/SC Hub | [B-SCHUB-CPP](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-GENERAL** General device (Annex L.8) | *(satisfied by every example above)* | — | — | — | — | — |

### Operator interfaces and workstations (Annex L.1–L.3, L.9–L.10, L.12)

Client-side profiles.

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-OD** Operator Display | [B-OD-CPP](https://github.com/chipkin/BACnetProfileExample-B-OD-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-OWS** Operator Workstation | planned | — | — | — | — | — |
| **B-AWS** Advanced Operator Workstation | planned | — | — | — | — | — |
| **B-XAWS** Extended Advanced Operator Workstation | planned | — | — | — | — | — |
| **B-LSAP** Life Safety Annunciator Panel | planned | — | — | — | — | — |
| **B-LSWS** Life Safety Workstation | planned | — | — | — | — | — |
| **B-ALSWS** Advanced Life Safety Workstation | planned | — | — | — | — | — |
| **B-ACSD** Access Control Security Display | planned | — | — | — | — | — |
| **B-ACWS** Access Control Workstation | planned | — | — | — | — | — |
| **B-AACWS** Advanced Access Control Workstation | planned | — | — | — | — | — |
| **B-LOD** Lighting Operator Display | planned | — | — | — | — | — |
| **B-ALWS** Advanced Lighting Workstation | planned | — | — | — | — | — |
| **B-LCS** Lighting Control Station | planned | — | — | — | — | — |
| **B-ALCS** Advanced Lighting Control Station | planned | — | — | — | — | — |
| **B-ED** Elevator Display | planned | — | — | — | — | — |
| **B-EWS** Elevator Workstation | planned | — | — | — | — | — |
| **B-AEWS** Advanced Elevator Workstation | planned | — | — | — | — | — |

🚧 = in progress. "Ask" = not yet built for that language; contact Chipkin if you need it. Profile definitions: ANSI/ASHRAE 135-2024 Annex L. BIBB definitions: Annex K. Get the stack: <https://store.chipkin.com/services/stacks/bacnet-stack>.
<!-- PROFILE-TABLE:END -->

## References

- **ANSI/ASHRAE Standard 135** (BACnet): objects (clause 12), services
  (clause 16), certificate management (clause 19.8), BACnet/SC (Annex AB),
  device profiles (Annex L). From the
  [ASHRAE store](https://www.ashrae.org/technical-resources/standards-and-guidelines).
- **CAS BACnet Stack**: <https://store.chipkin.com/services/stacks/bacnet-stack>.
- **CAS BACnet Explorer**: <https://store.chipkin.com/products/tools/cas-bacnet-explorer>.
- **What is BACnet?**: <https://docs.chipkin.com/protocols/bacnet/>.
- [CHANGELOG.md](CHANGELOG.md) - release history.
