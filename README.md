# BACnet/SC Hub (B-SCHUB) - C++ example

A BACnet Secure Connect (BACnet/SC) hub built on the
[CAS BACnet Stack](https://store.chipkin.com/services/stacks/bacnet-stack).
BACnet/SC devices connect to it over TLS 1.3 WebSockets and it relays their
BACnet traffic, the way a BACnet/IP broadcast domain does for UDP devices. It
also keeps a plain BACnet/IP port open, so you can find and manage it with
any BACnet/IP tool.

It implements the **B-SCHUB** device profile (ANSI/ASHRAE 135 Annex L) and
is meant both as a working hub and as a starting point for your own product.

- **[Download a prebuilt binary](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases)**
  (Windows and Linux x64), or [build it yourself](#build).
- **[docs/PICS.pdf](docs/PICS.pdf)** - the BACnet Protocol Implementation
  Conformance Statement (also as [Markdown](docs/PICS.md)).
- **[TUTORIAL.md](TUTORIAL.md)** - how the code works and how to adapt it.

This manual describes **version 1.2.0**. `BACnetExampleBSCHUB --version`
prints the version you are running, with the CAS BACnet Stack and `common/`
helper versions.

## Contents

- [Quick start](#quick-start)
- [What the hub does](#what-the-hub-does)
- [The BACnet device](#the-bacnet-device)
- [Certificates](#certificates)
- [Running the hub](#running-the-hub)
- [Connecting devices](#connecting-devices)
- [Managing certificates over BACnet](#managing-certificates-over-bacnet)
- [Status page and HTTP endpoints](#status-page-and-http-endpoints)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Build](#build)
- [Testing](#testing)
- [Licensing](#licensing)

## Quick start

```bash
# 1. Make a lab certificate set: a CA, the hub's certificate, and 3 device
#    certificates (clients/client-01 .. client-03).
BACnetExampleBSCHUB --generate-certs

# 2. Start the hub.
BACnetExampleBSCHUB
```

3. Open **<http://127.0.0.1:8080/>** in a browser. The status page shows the
   version, whether the BACnet/SC hub is listening, and live connection counts.
4. Give each BACnet/SC device one `certs/clients/<label>/` folder. In the
   Chipkin BACnet Explorer, import that folder's `bacnetsc.config`.

On Windows the program is `BACnetExampleBSCHUB.exe`. When built from source
it's under `build/` (Linux/macOS) or `build\Release\` (Windows).

## What the hub does

- **BACnet/SC hub function** (BIBB NM-SCH-B) on Network Port 2: listens on
  `wss://0.0.0.0:47819/` (TLS 1.3, mutual certificate authentication,
  WebSocket subprotocol `hub.bsc.bacnet.org`) and relays traffic between the
  connected devices (up to 4 at a time - see [Connection
  limit](#connection-limit)), including this hub's own BACnet device.
- **Optional hub connector**: with `--sc-hub-uri`, the hub also connects out
  to another BACnet/SC hub (with an optional failover hub).
- **BACnet/IP** on Network Port 1 (UDP 47808), always on: discovery
  (Who-Is/I-Am, Who-Has/I-Have), ReadProperty, ReadPropertyMultiple and
  DeviceCommunicationControl.
- **Certificate management over BACnet**: a client can add an issuer and
  replace the hub's operational certificate (ANSI/ASHRAE 135 clause 19.8.3).
- **Status page, health and metrics** over HTTP, for people and for
  monitoring tools.
- **Built-in lab certificate generator**, including a ready-to-import
  connection file for each device.

### Supported BIBBs

| BIBB | Name |
|---|---|
| DS-RP-B | Data Sharing - ReadProperty - B |
| DS-RPM-B | Data Sharing - ReadPropertyMultiple - B |
| DM-DDB-B | Device Management - Dynamic Device Binding - B |
| DM-DOB-B | Device Management - Dynamic Object Binding - B |
| DM-DCC-B | Device Management - DeviceCommunicationControl - B |
| NM-SCH-B | Network Management - BACnet/SC Hub Function - B |

### Services executed

| Service | Use |
|---|---|
| ReadProperty, ReadPropertyMultiple | Read any property of any object. |
| Who-Is / I-Am, Who-Has / I-Have | Discovery. The hub also broadcasts I-Am at startup. |
| DeviceCommunicationControl | Silence or resume the device, optionally with a password. |
| AtomicReadFile | Read the certificate File objects. |
| AtomicWriteFile, WriteProperty | Certificate management only: write a certificate into File 1, 3 or 4, and set their `File_Size`. No other property is writable. |
| ReinitializeDevice | `ACTIVATE_CHANGES` or `WARMSTART` applies written certificates. Other states are refused. |

The [PICS](docs/PICS.pdf) lists every object and property and who answers it.

## The BACnet device

```
Device 389022          "Chipkin Example B-SCHUB"       Vendor 389 (Chipkin Automation Systems)
├── Analog Input 1     "Bronze"                        example sensor value, degrees C
├── Network Port 1     "BACnet IP"                     BACnet/IP, UDP 47808
├── Network Port 2     "BACnet SC"                     BACnet/SC hub function (and optional connector)
├── File 1             "Operational Certificate"       the hub's certificate            (writable)
├── File 2             "Certificate Signing Request"   CSR for the hub's key            (read-only)
├── File 3             "Issuer Certificate Slot 1"     trusted CA certificate           (writable)
└── File 4             "Issuer Certificate Slot 2"     second trusted CA certificate    (writable)
```

Every object has a **Description** saying what it is for. The Device's
Description links back to this repository.

The device instance defaults to 389022; change it with `--deviceID` or the
config file's `device-id`. Analog Input 1 is example data: the up/down arrow
keys change it while the hub runs.

Both Network Ports report `Network_Number` 0 with `Network_Number_Quality`
**unknown**, because this device is not configured with a network number
and isn't a router. The private key is never served by any object.

## Certificates

BACnet/SC runs over TLS with **mutual authentication**: the hub and every
device present a certificate, and each side accepts the other only if that
certificate was signed by an issuer (CA) it trusts.

### Lab certificates

The hub can make a complete lab certificate set itself:

```bash
BACnetExampleBSCHUB --generate-certs        # CA + hub + 3 device certificates
BACnetExampleBSCHUB --generate-certs 10     # ... or any number of devices
```

This writes PEM files to `--sc-cert-dir` (default `./certs`) and exits. The
file names follow the Network Port properties that carry them (ANSI/ASHRAE
135 clause 12.56):

| File | What it is |
|---|---|
| `operational-certificate.pem` | The hub's certificate (File 1, Operational_Certificate_File). Its subjectAltName lists localhost, 127.0.0.1, this computer's host name and the hub URI's host. |
| `private-key.pem` | The hub's private key. **Private.** |
| `certificate-signing-request.pem` | CSR for the hub's key (File 2, Certificate_Signing_Request_File). |
| `issuer-certificate.pem` | The lab CA (File 3, Issuer_Certificate_Files). Every device needs a copy. |
| `issuer-private-key.pem` | The CA's private key, only used to sign more devices. **Private.** Keep it off the network. |
| `clients/<label>/` | One folder per device: its `operational-certificate.pem`, `private-key.pem` (**private**), `issuer-certificate.pem` and `bacnetsc.config`. |
| `certificates.txt` | Every certificate's label, location, serial number, expiry and SHA-256 fingerprint. |
| `readme.txt` | A walkthrough of the folder, including which files are private. |

The hub adds two files of its own: `issuer-certificate-2.pem` (File 4, once a
second issuer is written over BACnet) and `trusted-issuers.pem` (every issuer
from both slots; this is what TLS trusts).

Device certificates are labeled by folder and by subject Common Name
(`Chipkin Example B-SCHUB client-01`), so the hub's log shows which device
connected.

**Adding devices later.** Sign more device certificates with the *existing*
CA. Numbering continues, and a running hub trusts them straight away:

```bash
BACnetExampleBSCHUB --add-client-certs 2                    # clients/client-04, client-05
BACnetExampleBSCHUB --add-client-certs 3 --cert-label ahu   # clients/ahu-01 .. ahu-03
```

**Starting over.** `--generate-certs` won't replace an existing CA, because
every certificate already handed out would stop working. Add `--force` to
delete the whole set, including `clients/`, and make a new one.

The lab profile is ECDSA P-256 with SHA-256; the CA is valid for 10 years and
device certificates for 825 days. For a production site, use your own CA:
have it sign the hub's CSR (File 2), and install the result on disk or [over
BACnet](#managing-certificates-over-bacnet). Folders made by earlier releases
(`hub.crt`, `hub.key`, `ca.crt`) still work.

## Running the hub

```bash
BACnetExampleBSCHUB [options]
```

Typical startup:

```
BACnet B-SCHUB (BACnet/SC Hub) Example - C++ v1.2.0
CAS BACnet Stack version: 6.0.23.0
Common helper (common/) version: 3.0.0
FYI: Listening for BACnet/IP on UDP port 47808 (Network Port 1).
FYI: Device 389022 ("Chipkin Example B-SCHUB") ready. Vendor ID 389. Press 'h' for help, 'm' for a health/metrics snapshot.
BACnet/SC: listening for WebSocket/TLS connections on wss://0.0.0.0:47819/ (subprotocol "hub.bsc.bacnet.org", TLS 1.3, mutual auth)
```

At startup the hub also checks its certificates and logs the subject, days
until expiry (a warning under 30 days), whether the private key matches, and
the subjectAltName entries. Allow UDP 47808 and TCP 47819 through the firewall.

### Options

| Option | Default | Meaning |
|---|---|---|
| `--port <n>` | `47808` | BACnet/IP UDP port. |
| `--deviceID <n>` | `389022` | BACnet device instance. |
| `--sc-port <n>` | `47819` | BACnet/SC hub (wss://) port. |
| `--sc-cert-dir <dir>` | `./certs` | Certificate folder. |
| `--sc-hub-uri <wss://host:port/>` | off | Also connect out to this BACnet/SC hub. |
| `--sc-failover-uri <wss://host:port/>` | off | Failover hub for `--sc-hub-uri`. |
| `--sc-max-hub-connections <n>` | `4` | Maximum BACnet/SC devices connected at once, 1 to 4 (see [Connection limit](#connection-limit)). |
| `--sc-rate-limit <n>` | `10` | Maximum new connection attempts per second (0 = no limit). Excess attempts are refused before the TLS handshake. |
| `--http-port <n>` | `8080` | Status page and HTTP endpoints. |
| `--http-bind <addr>` | `127.0.0.1` | Interface for the HTTP listener. See [Security](#security) before changing it. |
| `--config <path>` | none | Read settings from a config file (below). |
| `--generate-certs [n]` | `3` | Make a lab certificate set with `n` device certificates, then exit. |
| `--add-client-certs [n]` | `1` | Sign `n` more device certificates with the existing CA, then exit. |
| `--cert-label <prefix>` | `client` | Label for new device certificates. |
| `--cert-hub-uri <wss://host:port/>` | this computer's IPv4 and `--sc-port` | Hub URI written into each device's `bacnetsc.config` (and the hub certificate's subjectAltName). |
| `--force` | - | With `--generate-certs`: replace an existing certificate set. |
| `--help`, `--version` | - | Usage, or version information. |

### Configuration file

`--config <path>` reads `key = value` lines (`#` starts a comment).
[`example.conf`](example.conf) lists every key with its default:
`device-id`, `port`, `sc-port`, `sc-cert-dir`, `sc-hub-uri`,
`sc-failover-uri`, `dcc-password`, `http-port`, `http-bind`,
`sc-max-hub-connections` and `sc-rate-limit`. A command-line option always
wins over the config file. An unknown key or bad value is logged and skipped.

**`dcc-password` can only be set in the config file**, so it never shows up in
process listings or shell history. It protects DeviceCommunicationControl,
ReinitializeDevice and the HTTP certificate upload. Restrict the file's
permissions (`chmod 600 example.conf`, or on Windows
`icacls example.conf /inheritance:r /grant:r "%USERNAME%:F"`); the hub warns
at startup if the file looks readable by other users.

### Connection limit

This example accepts **at most 4 BACnet/SC devices at a time**. It is for
evaluation and testing, not for production. You can lower the limit with
`--sc-max-hub-connections` or `sc-max-hub-connections` in the config file, but
not raise it: asking for more than 4 prints an error and the hub shuts down.

For a production BACnet/SC hub with more connections, contact Chipkin at
**sales@chipkin.com**.

### Console keys

| Key | Action |
|---|---|
| `h` | Help and version. |
| `m` | Health and metrics snapshot. |
| up / down | Change Analog Input 1 by 1.1. |
| `q` | Quit. |

## Connecting devices

For each BACnet/SC device:

1. Give it its own `certs/clients/<label>/` folder. Don't share a folder
   between devices: the hub couldn't tell them apart.
2. **Chipkin BACnet Explorer:** import the folder's `bacnetsc.config`. It
   names the hub URI and the folder's three PEM files, so keep them together.
3. **Any other BACnet/SC device:** install `operational-certificate.pem` and
   `private-key.pem` as its operational certificate and key, and
   `issuer-certificate.pem` as its issuer certificate. Set its primary hub URI
   to `wss://<hub address>:47819/`.

The hub URI in `bacnetsc.config` is this computer's LAN address unless you
generated the set with `--cert-hub-uri`. The hub logs every connection and
disconnection with the device's address, and refused TLS handshakes with the
reason.

## Managing certificates over BACnet

A BACnet client can change the hub's certificates with the BACnet/SC
certificate procedures (ANSI/ASHRAE 135 clause 19.8.3), for example from the
CAS BACnet Explorer's certificate page:

1. **Write** - WriteProperty `File_Size = 0`, then AtomicWriteFile the new PEM
   certificate: File 1 for the hub's own certificate, File 3 or 4 for an
   issuer.
2. **Staged** - reading the File back shows the new certificate and Network
   Port 2's `Changes_Pending` is TRUE, but nothing is saved yet and the hub
   keeps using its current certificates.
3. **Activate** - ReinitializeDevice `ACTIVATE_CHANGES` (or `WARMSTART`). The
   hub checks the staged certificates first: each must be a PEM certificate,
   at least one issuer must remain, and the hub certificate must match its
   private key and chain to an issuer. If they pass, it saves them and
   restarts BACnet/SC; devices reconnect under the new certificates. If not,
   it answers `INVALID_CONFIGURATION_DATA` and nothing changes, so a mistake
   can't lock the hub out. The staged writes stay, so the client can correct
   them and activate again.

Supported procedures:

- **Add an issuer** - write the new CA into slot 2 (File 4). Devices signed by
  either CA are then accepted, which lets a site move to a new CA gradually.
- **Replace the hub certificate** - read the CSR (File 2), have your CA sign
  it, write the result to File 1, activate.

Not yet supported: key-pair regeneration (`GENERATE_CSR_FILE`, waiting on
[cas-bacnet-stack#2976](https://github.com/chipkin/cas-bacnet-stack/issues/2976)),
and discarding staged writes with `DISCARD_CHANGES`
([#29](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/29)).
A restart discards staged writes.

If `dcc-password` is set, ReinitializeDevice requires it.

## Status page and HTTP endpoints

The hub serves HTTP on `--http-port` (default 8080), on `127.0.0.1` only by
default.

| Path | What it returns |
|---|---|
| `GET /` | Status page for a browser: versions, device, health, BACnet/SC state, metrics, and links to this project and the CAS BACnet Stack. Refreshes every 5 seconds. |
| `GET /health` | *Is the hub working?* JSON with `status` `ok` (HTTP 200) or `degraded` (HTTP 503 - the BACnet/SC hub isn't listening, usually because of missing or bad certificates). Point uptime monitors and load balancers here. |
| `GET /metrics` | *How much is it doing?* JSON counters: uptime, connected devices, connects, disconnects, rate-limit refusals, messages and bytes in and out. |
| `POST /certs/<slot>` | Upload a certificate file (`operational`, `csr`, `issuer1`, `issuer2`). Needs `Authorization: Bearer <dcc-password>`; disabled when no `dcc-password` is set. |

```
$ curl -s http://127.0.0.1:8080/health
{"status":"ok","version":"1.2.0","uptime_seconds":154,"sc_hub_function_listening":true,"sc_hub_connections_current":1,"staged_certificate_changes":false}

$ curl -s http://127.0.0.1:8080/metrics
{"uptime_seconds":154,"uptime":"2m 34s","sc_hub_connections_current":1,"sc_hub_connections_max":4,"sc_total_connects":3,"sc_total_disconnects":2,"sc_rate_limit_rejections":0,"sc_rx_messages":12,"sc_rx_bytes":456,"sc_tx_messages":12,"sc_tx_bytes":456}
```

An uploaded certificate is written to disk atomically and used from the next
BACnet/SC restart. Prefer [managing certificates over
BACnet](#managing-certificates-over-bacnet), which validates before
activating.

## Security

- **BACnet/SC** uses TLS 1.3 only, with mutual authentication. A device is
  accepted if its certificate chains to an issuer in File 3 or 4.
  Certificate revocation isn't checked
  ([#15](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/15)):
  to cut a device off, replace the issuer.
- **Host names aren't checked** when the hub connects out to another hub.
  BACnet/SC certificates identify devices, not DNS names; the certificate
  chain is still verified.
- **The HTTP listener has no TLS**
  ([#22](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/22)).
  It binds to 127.0.0.1 by default. If you need it from another machine, use
  an SSH tunnel or a TLS reverse proxy rather than `--http-bind`; the hub logs
  a warning on every start bound off loopback. `/`, `/health` and `/metrics`
  have no authentication.
- **Private keys** (`private-key.pem`, `issuer-private-key.pem`) must stay
  private. Keep the CA's key off the hub in production.
- **Rate limiting** (`--sc-rate-limit`) is one limit for the whole listener,
  not per source address
  ([#20](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/20)).
  On an untrusted network, add a per-address limit in a firewall.

Open items are tracked as [GitHub issues](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `cannot start listening ... certificate file(s) missing/unreadable` | No certificates in `--sc-cert-dir`. Run `--generate-certs`, or point `--sc-cert-dir` at your certificates. BACnet/IP keeps working. `/health` reports `degraded`. |
| `SC TLS handshake REJECTED - client certificate failed verification` | The device's certificate isn't signed by an issuer the hub trusts, or has expired. Check it with `openssl verify -CAfile issuer-certificate.pem operational-certificate.pem`. |
| `private key ... DOES NOT MATCH` at startup | `private-key.pem` and `operational-certificate.pem` are from different sets. |
| A device can't reach the hub | Check the hub URI in its `bacnetsc.config`, TCP 47819 in the firewall, and whether 4 devices are already connected (the [connection limit](#connection-limit)). |
| `ERROR: TOO MANY BACnet/SC CONNECTIONS REQUESTED` and the hub exits | `sc-max-hub-connections` is above 4. Set it to 4 or less. See [Connection limit](#connection-limit). |
| Red `Error:` lines at startup | Normal CAS BACnet Stack debug output (e.g. the hub hearing its own broadcast I-Am). See [TUTORIAL.md](TUTORIAL.md#troubleshooting). |

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

Cloned without `--recursive`? Run `git submodule update --init --recursive`
first. The first build compiles the CAS BACnet Stack (about 600 files) and,
the first time on a machine, OpenSSL (10-15 minutes); later builds are
incremental. After updating the stack submodule, run `cmake -B build` again
before building. To use a stack outside the submodule:
`cmake -B build -S . -D CAS_STACK_DIR=/path/to/cas-bacnet-stack`.

## Testing

`tests/sc/` holds the verification scripts; see its
[README](tests/sc/README.md). They need Python 3 and
`pip install -r tests/sc/requirements.txt`.

| Script | Checks |
|---|---|
| `hub_listener_test.py` | TLS 1.3 and subprotocol negotiation, refusal of bad clients, and a BACnet/SC Connect-Request/Accept. |
| `file_object_test.py` | The certificate File objects over BACnet/IP; the private key is never served. |
| `cert_procedure_test.py` | Certificate management over BACnet: add issuer, rejected activation, replace the hub certificate. |
| `fake_hub_server.py` | A test hub for the `--sc-hub-uri` connector. |
| `rpm_test.py` | ReadPropertyMultiple against the Device. |

CI runs these on Windows and Linux for every pull request.

## Licensing

- **This project** (everything outside `submodules/`) is public domain under
  [CC0-1.0](LICENSE).
- **CAS BACnet Stack** - a commercial Chipkin product, included as a private
  git submodule. You need a licence to build this project, not to use a
  [prebuilt release](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases).
  Contact <https://store.chipkin.com/services/stacks/bacnet-stack> or
  sales@chipkin.com.
- **libwebsockets** (MIT) and **OpenSSL 3** (Apache-2.0), via vcpkg. See
  [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

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
