# BACnet/SC Hub (B-SCHUB) - User Manual

**Version 1.3.0** · Chipkin Automation Systems ·
<https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP>

This manual is for people who install, configure and run the hub.
`BACnetExampleBSCHUB --version` prints the version you are running, with the
CAS BACnet Stack and `common/` helper versions. For how the code works and how
to build your own product from it, see [TUTORIAL.md](../TUTORIAL.md).

## Contents

1. [What the hub does](#1-what-the-hub-does)
2. [Installation](#2-installation)
3. [Quick start](#3-quick-start)
4. [Certificates](#4-certificates)
5. [Configuration](#5-configuration)
6. [Connecting devices](#6-connecting-devices)
7. [Managing certificates over BACnet](#7-managing-certificates-over-bacnet)
8. [Status page and HTTP endpoints](#8-status-page-and-http-endpoints)
9. [Security](#9-security)
10. [Troubleshooting](#10-troubleshooting)
11. [The BACnet device](#11-the-bacnet-device)
12. [Version, licensing and support](#12-version-licensing-and-support)

## 1. What the hub does

BACnet Secure Connect (BACnet/SC, ANSI/ASHRAE 135 Annex AB) carries BACnet
over TLS-secured WebSockets instead of plain UDP. Devices on a BACnet/SC
network don't talk to each other directly: each one connects to a **hub**,
which relays their traffic - the role a BACnet/IP broadcast domain plays for
UDP devices. This program is that hub, built on the
[CAS BACnet Stack](https://store.chipkin.com/services/stacks/bacnet-stack).

```
   BACnet/SC device  ─┐
   BACnet/SC device  ─┼─ wss:// (TLS 1.3, mutual auth) ─► BACnet/SC hub ◄─ UDP 47808 ─ BACnet/IP tools
   BACnet/SC device  ─┘                                  (this program)   (optional, for discovery
                                                                            and management)
```

It implements the **B-SCHUB** device profile (ANSI/ASHRAE 135 Annex L):

- **BACnet/SC hub function** (BIBB NM-SCH-B) on Network Port 2: listens on
  `wss://0.0.0.0:47819/` (TLS 1.3, mutual certificate authentication,
  WebSocket subprotocol `hub.bsc.bacnet.org`) and relays traffic between the
  connected devices (up to 4 at a time - see
  [Connection limit](#connection-limit)), including this hub's own BACnet
  device.
- **Optional hub connector**: with `--sc-hub-uri`, the hub also connects out
  to another BACnet/SC hub (with an optional failover hub).
- **BACnet/IP** on Network Port 1 (UDP 47808), on by default: discovery
  (Who-Is/I-Am, Who-Has/I-Have), ReadProperty, ReadPropertyMultiple and
  DeviceCommunicationControl. It can be turned off for a BACnet/SC-only site
  ([BACnet/SC only](#bacnetsc-only)).
- **Certificate management over BACnet**: a client can add an issuer and
  replace the hub's operational certificate (clause 19.8.3).
- **Status page, health and metrics** over HTTP or HTTPS, for people and for
  monitoring tools.
- **Built-in lab certificate generator**, including a ready-to-import
  connection file for each device.

This build is for **evaluation and testing**: it accepts at most 4 BACnet/SC
devices at a time. For a production hub, contact **support@chipkin.com**.

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
| Who-Is / I-Am, Who-Has / I-Have | Discovery. The hub also broadcasts I-Am at startup over BACnet/IP. |
| DeviceCommunicationControl | Silence or resume the device, optionally with a password. |
| AtomicReadFile | Read the certificate File objects. |
| AtomicWriteFile, WriteProperty | Certificate management only: write a certificate into File 1, 3 or 4, and set their `File_Size`. No other property is writable. |
| ReinitializeDevice | `ACTIVATE_CHANGES` or `WARMSTART` applies written certificates. Other states are refused. |

The [PICS](PICS.pdf) lists every object and property and who answers it.

## 2. Installation

Download from the
[Releases page](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases):

| Download | What it is |
|---|---|
| `BACnetSCHub-<version>-setup.exe` | **Windows installer.** Installs the program in `C:\Program Files\Chipkin\BACnet SC Hub`; settings, certificates and logs go in `C:\ProgramData\Chipkin\BACnetSCHub`. Optionally sets up the **BACnetSCHub** Windows service (starts on boot, restarts on failure) and firewall rules for UDP 47808 and TCP 47819. |
| `bacnet-schub-hub_<version>_amd64.deb` | **Debian/Ubuntu package**: `sudo apt install ./bacnet-schub-hub_<version>_amd64.deb`. The program goes in `/opt/bacnet-schub`, settings in `/etc/bacnet-schub/hub.conf`, certificates in `/etc/bacnet-schub/certs`, logs in `/var/log/bacnet-schub`, and the **bacnet-schub-hub** systemd service is enabled and started, running as the `bacnethub` user. |
| `BACnetSCHub-<version>-linux-x64.tar.gz` | The same for other Linux distributions: unpack it and run `sudo ./install.sh`. `sudo ./uninstall.sh` removes it (`--purge` also removes settings and certificates). |
| `BACnetExampleBSCHUB.exe`, `BACnetExampleBSCHUB` | The bare program, to run from a folder of your choice. |
| `manual.pdf`, `fact-sheet.pdf`, `PICS.pdf` | This manual, the two-page fact sheet, and the PICS. |
| `sbom-windows.cdx.json`, `sbom-linux.cdx.json` | Software bill of materials: the exact CAS BACnet Stack, OpenSSL, libwebsockets and other library versions. |
| `SHA256SUMS.txt` | SHA-256 checksums of every download: `sha256sum -c SHA256SUMS.txt --ignore-missing`. |

Both installers make a lab certificate set if the certificate folder is
empty, so the hub starts listening straight away; replace it for production
(see [Certificates](#4-certificates)). Settings and certificates are kept
when you upgrade or uninstall.

**Signed downloads.** The Windows program and the Windows installer are
code-signed by Chipkin (Azure Artifact Signing, SHA-256 with a timestamp);
check them with `Get-AuthenticodeSignature <file>`. Every download - the
Linux archive and `.deb` included - also has a signed build-provenance
attestation: `gh attestation verify <file> --repo
chipkin/BACnetProfileExample-B-SCHUB-CPP` confirms it was built by this
project's release workflow. `SHA256SUMS.txt` lists every file's checksum. See
[code-signing.md](code-signing.md#checking-a-release).

### Supported platforms

Windows 10/11 and Windows Server 2016 or later (x64). Linux x64: the release
build is made on the current Ubuntu LTS, so it needs a distribution with that
glibc version or newer; for an older distribution, build from source (see the
README). The hub also builds from source on macOS.

The hub runs fine on Windows 10, but BACnet/SC tools on a Windows 10
computer that use Windows' own TLS (such as YABE) can't connect to it or to
any other BACnet/SC hub: BACnet/SC requires TLS 1.3, and Windows 10 can't
make TLS 1.3 client connections. The hub logs a warning about this when it
starts on Windows 10
([#39](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/39)).

### Firewall

Allow in:

| Port | Protocol | For |
|---|---|---|
| 47819 | TCP | BACnet/SC devices connecting to the hub (`--sc-port`). |
| 47808 | UDP | BACnet/IP discovery and management (`--port`), unless BACnet/IP is off. |
| 8080 | TCP | The status page and HTTP endpoints (`--http-port`) - only if you bind it beyond 127.0.0.1. |

The Windows installer can add the first two rules for you.

### Running as a service

**Windows.** The installer sets up the **BACnetSCHub** service. To do it by
hand, from an Administrator command prompt:

```
BACnetExampleBSCHUB --install-service --config C:\ProgramData\Chipkin\BACnetSCHub\hub.conf
sc start BACnetSCHub
BACnetExampleBSCHUB --uninstall-service
```

The service runs `BACnetExampleBSCHUB --service --config <file>` with the
config file's folder as its working directory, so relative paths in it
(`sc-cert-dir = certs`, `log-file = logs\hub.log`) are relative to that
folder. There is no console, so use `log-file` to keep a log. The service
starts on boot and is restarted after 5, 30 and then 60 seconds if it fails.

**Linux (systemd).** The `.deb` and `install.sh` install
`bacnet-schub-hub.service`, which runs the hub with
`/etc/bacnet-schub/hub.conf`, restarts it on failure, and sends its output to
the journal as well as `log-file`:

```
systemctl status bacnet-schub-hub
journalctl -u bacnet-schub-hub -f
sudo systemctl restart bacnet-schub-hub     # after editing hub.conf
```

`systemctl stop` sends SIGTERM, which stops the hub cleanly, like pressing
`q`.

## 3. Quick start

From a folder where you unpacked the program:

```bash
# 1. Make a lab certificate set: a CA, the hub's certificate, and 3 device
#    certificates (clients/client-01 .. client-03).
BACnetExampleBSCHUB --generate-certs

# 2. Start the hub.
BACnetExampleBSCHUB
```

3. Open **<http://127.0.0.1:8080/>** in a browser. The status page shows the
   version, whether the BACnet/SC hub is listening, and the connected
   devices.
4. Give each BACnet/SC device one `certs/clients/<label>/` folder. In the
   [CAS BACnet Explorer](https://store.chipkin.com/products/tools/cas-bacnet-explorer), import that folder's `bacnetsc.config` (see
   [Connecting devices](#6-connecting-devices)).

On Windows the program is `BACnetExampleBSCHUB.exe`. A typical start-up:

```
BACnet B-SCHUB (BACnet/SC Hub) Example - C++ v1.3.0
CAS BACnet Stack version: 6.0.23.0
Common helper (common/) version: 3.0.0
FYI: Listening for BACnet/IP on UDP port 47808 (Network Port 1).
FYI: Device 389022 ("Chipkin Example B-SCHUB") ready. Vendor ID 389. Press 'h' for help, 'm' for a health/metrics snapshot.
BACnet/SC: listening for WebSocket/TLS connections on wss://0.0.0.0:47819/ (subprotocol "hub.bsc.bacnet.org", TLS 1.3, mutual auth)
```

At start-up the hub also checks its certificates and logs each one's subject,
days until expiry (a warning under 30 days), whether the private key matches,
and the subjectAltName entries.

### Console keys

| Key | Action |
|---|---|
| `h` | Help and version. |
| `m` | Health and metrics snapshot. |
| up / down | Change Analog Input 1 by 1.1. |
| `q` | Quit. |

## 4. Certificates

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
| `clients/<label>/` | One folder per device: its `operational-certificate.pem`, `private-key.pem` (**private**), `issuer-certificate.pem`, `bacnetsc.config` (CAS BACnet Explorer), and for Windows tools such as YABE `<label>.pfx` (certificate + key + issuer, empty password, **private**), `issuer-certificate.cer` (DER) and `yabe-bacnetsc.config`. |
| `certificates.txt` | Every certificate's label, location, serial number, expiry and SHA-256 fingerprint. |
| `readme.txt` | A walkthrough of the folder, including which files are private. |

The hub adds two files of its own: `issuer-certificate-2.pem` (File 4, once a
second issuer is written over BACnet) and `trusted-issuers.pem` (every issuer
from both slots; this is what TLS trusts). You can add a third,
`issuer-crl.pem`, to revoke device certificates (see
[Security](#9-security)).

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
device certificates for 825 days. Folders made by earlier releases
(`hub.crt`, `hub.key`, `ca.crt`) still work.

### Production certificates

For a production site, use your own CA: have it sign the hub's CSR (File 2),
and install the result on disk or [over BACnet](#7-managing-certificates-over-bacnet).
[production-certificates.md](production-certificates.md) walks through it:
using a site or enterprise CA (root and intermediate), getting the hub's
certificate signed, rotating certificates and changing the CA without an
outage, revocation, what the certificates should contain, and protecting
private keys.

## 5. Configuration

```bash
BACnetExampleBSCHUB [options]
```

### Options

| Option | Default | Meaning |
|---|---|---|
| `--port <n>` | `47808` | BACnet/IP UDP port. |
| `--bacnet-ip <on/off>` | `on` | `off` runs BACnet/SC only - see [BACnet/SC only](#bacnetsc-only). |
| `--deviceID <n>` | `389022` | BACnet device instance. |
| `--device-name <name>` | `Chipkin Example B-SCHUB` | The Device's `Object_Name`. Must be unique on the BACnet internetwork, so name each hub. |
| `--ip-network-number <n>`, `--sc-network-number <n>` | not set | `Network_Number` of Network Port 1 / 2 (1..65534), reported with quality `configured`. Unset ports report 0, quality `unknown`. |
| `--log-file <path>` | none | Also write everything the hub prints to this file (see [Logging](#logging)). |
| `--log-max-size-mb <n>`, `--log-max-files <n>` | `10`, `5` | Rotate the log file at this size, keeping this many old files (`<path>.1`, `.2`, ...). |
| `--sc-port <n>` | `47819` | BACnet/SC hub (wss://) port. |
| `--sc-cert-dir <dir>` | `./certs` | Certificate folder. |
| `--sc-hub-uri <wss://host:port/>` | off | Also connect out to this BACnet/SC hub. |
| `--sc-failover-uri <wss://host:port/>` | off | Failover hub for `--sc-hub-uri`. |
| `--sc-max-hub-connections <n>` | `4` | Maximum BACnet/SC devices connected at once, 1 to 4 (see [Connection limit](#connection-limit)). |
| `--sc-rate-limit <n>` | `10` | Maximum new BACnet/SC connection attempts per second from any one source address (0 = no limit). Excess attempts are refused before the TLS handshake. |
| `--sc-rate-limit-total <n>` | `50` | Maximum new BACnet/SC connection attempts per second for the whole listener (0 = no limit). |
| `--sc-accept-hub-without-hello` | off | Compatibility: let `--sc-hub-uri` connect to a hub that omits the Hello option. See [BACnet/SC compatibility](#bacnetsc-compatibility). |
| `--http-port <n>` | `8080` | Status page and HTTP endpoints. |
| `--http-bind <addr>` | `127.0.0.1` | Interface for the HTTP listener. See [Security](#9-security) before changing it. |
| `--http-tls` | off | Serve the HTTP endpoints over HTTPS. |
| `--http-tls-cert <file>`, `--http-tls-key <file>` | the hub's operational certificate and key | Certificate and key for `--http-tls`. |
| `--config <path>` | none | Read settings from a config file (below). |
| `--generate-certs [n]` | `3` | Make a lab certificate set with `n` device certificates, then exit. |
| `--add-client-certs [n]` | `1` | Sign `n` more device certificates with the existing CA, then exit. |
| `--cert-label <prefix>` | `client` | Label for new device certificates. |
| `--cert-hub-uri <wss://host:port/>` | this computer's IPv4 and `--sc-port` | Hub URI written into each device's `bacnetsc.config` (and the hub certificate's subjectAltName). |
| `--force` | - | With `--generate-certs`: replace an existing certificate set. |
| `--install-service`, `--uninstall-service` | - | Windows: set up or remove the BACnetSCHub service (see [Running as a service](#running-as-a-service)). |
| `--help`, `--version` | - | Usage, or version information. |

### Configuration file

`--config <path>` reads `key = value` lines (`#` starts a comment).
`example.conf` (shipped with the program) lists every key with its default:
`device-id`, `device-name`, `ip-network-number`, `sc-network-number`,
`log-file`, `log-max-size-mb`, `log-max-files`, `port`, `bacnet-ip`,
`sc-port`, `sc-cert-dir`, `sc-hub-uri`, `sc-failover-uri`, `dcc-password`,
`http-upload-token`, `http-port`, `http-bind`, `http-tls`, `http-tls-cert`,
`http-tls-key`, `sc-max-hub-connections`, `sc-rate-limit`,
`sc-rate-limit-total` and `sc-accept-hub-without-hello`. On/off keys take
`true`/`false` (or `on`/`off`, `yes`/`no`, `1`/`0`). A command-line option
always wins over the config file. An unknown key or bad value is logged and
skipped.

**`dcc-password` and `http-upload-token` can only be set in the config
file**, so they never show up in process listings or shell history.
`dcc-password` protects DeviceCommunicationControl and ReinitializeDevice;
`http-upload-token` is the separate secret for the HTTP certificate upload
(use a different value - the hub warns if they match). Both are compared in
constant time. Restrict the file's permissions (`chmod 600 hub.conf`, or on
Windows `icacls hub.conf /inheritance:r /grant:r "%USERNAME%:F"`); the hub
warns at start-up if the file looks readable by other users.

### Logging

Everything the hub prints goes to the console. With `--log-file <path>`
(config: `log-file`) it also goes to that file, which is appended to across
restarts. When the file reaches `--log-max-size-mb` (default 10 MB) it is
renamed `<path>.1` (the previous `.1` becomes `.2`, and so on) and a new file
is started; `--log-max-files` (default 5) old files are kept. Every line
written through the hub's logger starts with a UTC timestamp and a level
(`[INFO]`, `[WARN]`, `[ERROR]`). Connection audit lines start with
`SC audit:`.

### BACnet/SC only

Some sites want no unencrypted BACnet traffic at all. `--bacnet-ip off`
(config: `bacnet-ip = off`) turns BACnet/IP off: the hub opens no UDP port,
Network Port 1 doesn't exist (it isn't in the Device's `Object_List`), and
the device is reachable only over BACnet/SC - discovery (Who-Is/I-Am) and
every other service go through the hub. It doesn't send an I-Am at start-up,
since no BACnet/SC device is connected yet; devices find it with Who-Is once
they connect.

The hub warns at start-up if BACnet/IP is off and BACnet/SC isn't listening
(missing or bad certificates, say), because the device can't then be reached
over BACnet at all. BACnet/SC keeps retrying every 5 seconds, and `/health`
reports `degraded` until it is listening; the status page and `/health`
(`bacnet_ip_enabled`) show which mode the hub is in.

### BACnet/SC compatibility

ANSI/ASHRAE 135-2024 (clause AB.2.2) requires the BACnet/SC Connect-Request
and Connect-Accept messages to carry a *Hello* option. By default the hub
follows the standard strictly and refuses a connection that leaves it out.

`--sc-accept-hub-without-hello` (config: `sc-accept-hub-without-hello =
true`) relaxes this for the **hub connector** only: when the hub connects out
to another hub (`--sc-hub-uri`), it accepts that hub's Connect-Accept without
Hello and treats the other hub as having no optional capabilities. Turn it on
only for a hub that needs it; the hub logs a warning at start-up while it is
on.

It does **not** change what this hub accepts from devices. A device that
connects to this hub with a Connect-Request without Hello (some YABE versions
do) is still refused: the CAS BACnet Stack has no setting for that yet.

### Connection limit

This example accepts **at most 4 BACnet/SC devices at a time**. It is for
evaluation and testing, not for production. You can lower the limit with
`--sc-max-hub-connections` or `sc-max-hub-connections` in the config file, but
not raise it: asking for more than 4 prints an error and the hub shuts down.

For a production BACnet/SC hub with more connections, contact Chipkin at
**support@chipkin.com**.

## 6. Connecting devices

For each BACnet/SC device:

1. Give it its own `certs/clients/<label>/` folder. Don't share a folder
   between devices: the hub couldn't tell them apart.
2. **[CAS BACnet Explorer](https://store.chipkin.com/products/tools/cas-bacnet-explorer):** import the folder's `bacnetsc.config`. It
   names the hub URI and the folder's three PEM files, so keep them together.
3. **YABE (Yet Another BACnet Explorer):** in *Communication Channel* ->
   *BACnet/Secure Connect*, **Select** the folder's `yabe-bacnetsc.config`,
   then **Start**. It points at the folder's `<label>.pfx` (certificate,
   key and issuer, with an empty password - keep it private) and
   `issuer-certificate.cer` by absolute path, so re-select it if you move
   the folder. YABE uses Windows' own TLS, which can't make the TLS 1.3
   connections BACnet/SC requires on Windows 10: use Windows 11 / Server
   2022 or later
   ([#39](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/39)).
4. **Any other BACnet/SC device:** install `operational-certificate.pem` and
   `private-key.pem` as its operational certificate and key, and
   `issuer-certificate.pem` as its issuer certificate. Set its primary hub URI
   to `wss://<hub address>:47819/`.

The hub URI in `bacnetsc.config` is this computer's LAN address unless you
generated the set with `--cert-hub-uri`. The hub logs refused TLS handshakes
with the reason, and keeps an audit trail of every connection (lines start
with `SC audit:`): the device's address and the subject of the certificate it
presented, then its BACnet/SC VMAC and device UUID once the hub accepts it,
and the same identity again when it disconnects:

```
2026-09-26 18:10:21 [INFO] SC audit: peer "wss://0.0.0.0:47819/|client=3" connected from 10.0.0.31:64150, certificate "O = Chipkin Automation Systems (lab test), CN = Chipkin Example B-SCHUB client-01"
2026-09-26 18:10:21 [INFO] SC audit: peer "wss://0.0.0.0:47819/|client=3" (10.0.0.31:64150) is BACnet/SC device VMAC 0a:0b:0c:0d:0e:0f, UUID 50515253-5455-5657-5859-5a5b5c5d5e5f, certificate "O = Chipkin Automation Systems (lab test), CN = Chipkin Example B-SCHUB client-01" - connected
```

The status page lists the devices connected right now the same way.

## 7. Managing certificates over BACnet

A BACnet client can change the hub's certificates with the BACnet/SC
certificate procedures (ANSI/ASHRAE 135 clause 19.8.3), for example from the
[CAS BACnet Explorer](https://store.chipkin.com/products/tools/cas-bacnet-explorer)'s certificate page:

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

Not yet supported: the Network Port `Command` property, so neither key-pair
regeneration (`GENERATE_CSR_FILE`, waiting on
[cas-bacnet-stack#2976](https://github.com/chipkin/cas-bacnet-stack/issues/2976))
nor `DISCARD_CHANGES`
([#29](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/29)).
To drop staged writes, write the file's original contents back, or restart
the hub (a restart discards staged writes).

**Known issue:** right after the hub starts, Network Port 2 reads
`Changes_Pending` = TRUE (and `Current_Health` may report
`invalid-configuration-data`) although nothing has been written. The CAS
BACnet Stack leaves the hub's own start-up certificate settings pending
(cas-bacnet-stack#2866,
[#41](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/41)).
The certificates in use are correct. The first ReinitializeDevice
`ACTIVATE_CHANGES` clears it.

If `dcc-password` is set, ReinitializeDevice requires it.

## 8. Status page and HTTP endpoints

The hub serves HTTP on `--http-port` (default 8080), on `127.0.0.1` only by
default. With `--http-tls` it serves HTTPS instead (TLS 1.2 or 1.3), using the
hub's own `operational-certificate.pem` and `private-key.pem` unless
`--http-tls-cert`/`--http-tls-key` name another certificate - for example one
your browsers already trust. With the lab certificates, point curl at the lab
CA: `curl --cacert certs/issuer-certificate.pem https://localhost:8080/health`
(with Windows' own curl, add `--ssl-no-revoke`: the lab CA publishes no
revocation list for Windows to check). The HTTPS certificate is loaded at
start-up.

| Path | What it returns |
|---|---|
| `GET /` | Status page for a browser: versions, device, health, BACnet/SC state, metrics, the connected devices (address, certificate, VMAC and UUID), and links to this project and the CAS BACnet Stack. Refreshes every 5 seconds. |
| `GET /health` | *Is the hub working?* JSON with `status` `ok` (HTTP 200) or `degraded` (HTTP 503 - the BACnet/SC hub isn't listening, usually because of missing or bad certificates). Point uptime monitors and load balancers here. |
| `GET /metrics` | *How much is it doing?* JSON counters: uptime, connected devices, connects, disconnects, rate-limit refusals, messages and bytes in and out, and connections closed because the device stopped reading (`sc_tx_queue_overflows`). |
| `POST /certs/<slot>` | Upload a certificate file (`operational`, `csr`, `issuer1`, `issuer2`). Needs `Authorization: Bearer <http-upload-token>`; disabled when no `http-upload-token` is set. At most 5 attempts a minute from one address and 30 in total; more get HTTP 429 and a log line. |

```
$ curl -s http://127.0.0.1:8080/health
{"status":"ok","version":"1.3.0","uptime_seconds":154,"bacnet_ip_enabled":true,"sc_hub_function_listening":true,"sc_hub_connections_current":1,"staged_certificate_changes":false}

$ curl -s http://127.0.0.1:8080/metrics
{"uptime_seconds":154,"uptime":"2m 34s","sc_hub_connections_current":1,"sc_hub_connections_max":4,"sc_total_connects":3,"sc_total_disconnects":2,"sc_rate_limit_rejections":0,"sc_rx_messages":12,"sc_rx_bytes":456,"sc_tx_messages":12,"sc_tx_bytes":456,"sc_tx_queue_overflows":0}
```

### Uploading a certificate

An upload is checked exactly like a certificate written
[over BACnet](#7-managing-certificates-over-bacnet) before anything is saved:
it must be a PEM certificate, and the certificates as they would be afterwards
must still let the hub run (the hub certificate matches its private key and
chains to an issuer, and at least one issuer remains). If they pass, the file
is written atomically and BACnet/SC reloads with it straight away; devices
reconnect. If not, the hub answers HTTP 400 with the reason and nothing
changes. An upload to `csr` must be a certificate signing request for the
hub's own private key. While a certificate change made over BACnet is waiting
for `ACTIVATE_CHANGES`, uploads are refused with HTTP 409.

```
curl -X POST --data-binary @new-hub-cert.pem \
     -H "Authorization: Bearer $UPLOAD_TOKEN" http://127.0.0.1:8080/certs/operational
```

## 9. Security

- **BACnet/SC** uses TLS 1.3 only, with mutual authentication. A device is
  accepted if its certificate chains to an issuer in File 3 or 4, and isn't
  revoked (below).
- **Certificate revocation.** Put your CA's certificate revocation list(s) in
  `issuer-crl.pem` in `--sc-cert-dir` (PEM; one CRL per issuer, concatenated).
  The hub then refuses any device whose certificate is on a list. It checks
  the file every 5 seconds: a new or changed file restarts BACnet/SC, every
  device reconnects, and revoked ones are refused, so no restart is needed.
  Revocation checking fails closed: while the file exists, a device whose
  issuer has no CRL in it, or whose CRL is past its next-update date, is
  refused too, and a file with no readable CRL stops BACnet/SC (`/health`
  reports `degraded`). Keep the CRLs current. Without the file, revocation
  isn't checked. The start-up log lists each CRL, how many certificates it
  revokes, and when it expires.
- **Host names aren't checked** when the hub connects out to another hub.
  BACnet/SC certificates identify devices, not DNS names; the certificate
  chain is still verified.
- **The HTTP listener** binds to 127.0.0.1 by default. If you need it from
  another machine, turn on `--http-tls` before `--http-bind`, so the upload
  token and status data are encrypted (or use an SSH tunnel or a TLS reverse
  proxy). The hub logs a warning on every start bound off loopback over plain
  HTTP. `/`, `/health` and `/metrics` have no authentication, even over HTTPS.
- **Private keys** (`private-key.pem`, `issuer-private-key.pem`) must stay
  private. Keep the CA's key off the hub in production.
- **Rate limiting**: new BACnet/SC connection attempts are limited per
  source address (`--sc-rate-limit`, default 10 a second) and for the whole
  listener (`--sc-rate-limit-total`, default 50 a second), before the TLS
  handshake. One flooding host uses up only its own allowance, so devices on
  other addresses can still reconnect. The hub logs each refusal with the
  address. A device that stops reading is disconnected after 64 messages are
  waiting for it.
- **Unencrypted BACnet.** BACnet/IP (UDP 47808) is plain text. Turn it off
  with `--bacnet-ip off` where only BACnet/SC should be used.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `cannot start listening ... certificate file(s) missing/unreadable` | No certificates in `--sc-cert-dir`. Run `--generate-certs`, or point `--sc-cert-dir` at your certificates. BACnet/IP keeps working. `/health` reports `degraded`. |
| `lws_create_context failed ... retrying every 5 s` | The BACnet/SC port is in use, or a certificate file doesn't load. The hub keeps retrying; fix the cause and it starts listening without a restart. |
| `SC TLS handshake REJECTED - client certificate failed verification` | The device's certificate isn't signed by an issuer the hub trusts, has expired, or is revoked (`certificate revoked`, `unable to get certificate CRL` when `issuer-crl.pem` has no CRL for its issuer, `CRL has expired`). Check it with `openssl verify -CAfile issuer-certificate.pem operational-certificate.pem` (add `-crl_check -CRLfile issuer-crl.pem` with a CRL). |
| `private key ... DOES NOT MATCH` at start-up | `private-key.pem` and `operational-certificate.pem` are from different sets. |
| A device can't reach the hub | Check the hub URI in its `bacnetsc.config`, TCP 47819 in the firewall, and whether 4 devices are already connected (the [connection limit](#connection-limit)). The `SC audit:` lines show what the hub saw. |
| `refusing a WebSocket upgrade ... (HTTP 400)` | The device asked for a WebSocket subprotocol other than `hub.bsc.bacnet.org`. Check its BACnet/SC settings. |
| `Connect-Request refused by the hub` | Another connected device has the same VMAC, or the hub is full. |
| `SC rate limit: refusing a new connection` | A device (or something else) is reconnecting faster than `--sc-rate-limit` allows. |
| `ERROR: TOO MANY BACnet/SC CONNECTIONS REQUESTED` and the hub exits | `sc-max-hub-connections` is above 4. Set it to 4 or less. See [Connection limit](#connection-limit). |
| `/health` is `degraded` and BACnet/IP is off | BACnet/SC isn't listening, so the device is unreachable over BACnet. Fix the certificates, or run with `--bacnet-ip on`. |
| Red `Error:` lines at start-up | Normal CAS BACnet Stack debug output (e.g. the hub hearing its own broadcast I-Am). |
| A BACnet/SC tool on Windows 10 (e.g. YABE) fails with `A call to SSPI failed` / a TLS handshake error, and the hub logs nothing | Windows 10's own TLS can't do TLS 1.3, which BACnet/SC requires. The hub warns about this at start-up on Windows 10. Run the tool on Windows 11 / Server 2022 or later, or use a client with its own TLS 1.3 (CAS BACnet Explorer). See [#39](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/39). |
| The Windows service doesn't start | Check `log-file` in the service's `hub.conf`, and Windows Event Viewer > Windows Logs > System for Service Control Manager errors. |

## 11. The BACnet device

```
Device 389022          "Chipkin Example B-SCHUB"       Vendor 389 (Chipkin Automation Systems)
├── Analog Input 1     "Bronze"                        example sensor value, degrees C
├── Network Port 1     "BACnet IP"                     BACnet/IP, UDP 47808 (absent with --bacnet-ip off)
├── Network Port 2     "BACnet SC"                     BACnet/SC hub function (and optional connector)
├── File 1             "Operational Certificate"       the hub's certificate            (writable)
├── File 2             "Certificate Signing Request"   CSR for the hub's key            (read-only)
├── File 3             "Issuer Certificate Slot 1"     trusted CA certificate           (writable)
└── File 4             "Issuer Certificate Slot 2"     second trusted CA certificate    (writable)
```

Every object has a **Description** saying what it is for. The Device's
Description links back to the project.

The device instance defaults to 389022 (`--deviceID`), and the Device's name
to "Chipkin Example B-SCHUB" (`--device-name`). Both must be unique on the
BACnet internetwork. Analog Input 1 is example data: the up/down arrow keys
change it while the hub runs.

Each Network Port reports `Network_Number` 0 with `Network_Number_Quality`
**unknown** unless `--ip-network-number` / `--sc-network-number` sets it;
this device isn't a router. The private key is never served by any object.
The [PICS](PICS.pdf) lists every property.

## 12. Version, licensing and support

- **Version**: this manual describes version 1.3.0. What changed in each
  release is in [CHANGELOG.md](../CHANGELOG.md); what a version number
  promises is in [SUPPORT.md](SUPPORT.md).
- **Licensing**: the hub's own source code is public domain (CC0-1.0). It is
  built on the **CAS BACnet Stack**, a commercial Chipkin product, and on
  OpenSSL (Apache-2.0), libwebsockets (MIT), libuv (MIT), zlib (Zlib) and, on
  Windows, pthreads4w (Apache-2.0) - see
  [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md). Each release's
  `sbom-*.cdx.json` lists the exact versions.
- **Support**: questions and bug reports go to
  [GitHub issues](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues).
  For commercial support, a production hub or a CAS BACnet Stack licence,
  contact **support@chipkin.com**. Security problems: [SECURITY.md](../SECURITY.md).
- **Related documents**: the [fact sheet](fact-sheet.pdf), the
  [PICS](PICS.pdf), the [production certificate guide](production-certificates.md)
  and the [BTL test plan](BTL-TESTING.md).
