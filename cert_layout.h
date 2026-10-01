// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CERT_LAYOUT_H
#define BSCHUB_EXAMPLE_CERT_LAYOUT_H

// cert_layout.h
// =============================================================================
// Where the hub's certificate files are in --sc-cert-dir. The ONE place that
// knows the file names; everything else asks ResolveHubCertPaths().
//
// A folder made by this release is a CARI tree (Certificate Authority
// Requirements Interchange, ANSI/ASHRAE 135-2024 Annex AA.2, Addendum cs to
// 135-2020) for the hub itself (issue #71):
//
//   <sc-cert-dir>/
//     cert1/                               only CARI files in here
//       device-<instance>/port-2/
//         hub/                             empty: this port is a hub function
//         csr-hub.pem                      File 2  Certificate_Signing_Request_File
//         opr-hub.pem                      File 1  Operational_Certificate_File
//         key-hub.pem                      the operational certificate's key (no File object)
//       issuer/iss-1.pem                   File 3  Issuer_Certificate_Files[1]
//       issuer/iss-2.pem                   File 4  Issuer_Certificate_Files[2] (optional)
//     ca/ca-cert.pem, ca/ca-key.pem        the lab CA that signs devices (not CARI)
//     key-hub-pending.pem                  GENERATE_CSR_FILE's new key, until activated
//     trusted-issuers.pem, issuer-crl.pem, certificates.txt, readme.txt
//     clients/<label>/                     one CARI response per device
//
// Folders made by earlier releases keep working unchanged: the 1.4/1.5 flat
// names (operational-certificate.pem, private-key.pem, ...) and the older
// hub.crt/hub.key/hub.csr/ca.crt/ca.key. --migrate-certs copies either into a
// CARI tree.
// =============================================================================

#include <stdint.h>

#include <string>

namespace CertLayout {

enum class Kind {
    Cari,    // cert1/ tree (this release)
    Flat,    // operational-certificate.pem ... (1.4, 1.5 before the CARI change)
    Legacy,  // hub.crt, hub.key, hub.csr, ca.crt, ca.key (earlier releases)
};

// The CARI port folder the hub uses for itself: Network Port 2 "BACnet SC".
static const char* const HUB_PORT_ID = "2";
// The <string> in the hub's own csr-/opr-/key- file names.
static const char* const HUB_FILE_NAME = "hub";

struct HubCertPaths {
    Kind kind = Kind::Cari;
    std::string certDir;
    // CARI only: the port folder in use (relative to certDir), e.g.
    // "cert1/device-389022/port-2", and the instance in its name.
    std::string portFolder;
    uint32_t folderDeviceInstance = 0;
    // A note for the start-up log, e.g. that the folder's device instance
    // differs from the device's own. Empty if nothing to say.
    std::string note;

    // Full paths. Every one is set, whether or not the file exists yet.
    std::string operationalCertificate;  // File 1
    std::string certificateSigningRequest;  // File 2
    std::string issuerCertificate1;      // File 3
    std::string issuerCertificate2;      // File 4 (may not exist: then it serves File 3)
    std::string privateKey;
    std::string pendingPrivateKey;       // GENERATE_CSR_FILE
    std::string caCertificate;           // the CA that signs devices
    std::string caPrivateKey;
    std::string trustedIssuers;          // written by the hub at start-up
    std::string revocationList;          // issuer-crl.pem (optional, from the site's CA)
    std::string manifest;                // certificates.txt
    std::string readme;                  // readme.txt
    std::string clientsDir;              // clients/

    const char* KindName() const;
};

// Works out the layout of certDir. `deviceInstance` names the CARI device
// folder for a new set; an existing CARI tree is found by looking for
// cert1/device-*/port-*/hub/, so a changed --deviceID doesn't lose it.
HubCertPaths ResolveHubCertPaths(const std::string& certDir, uint32_t deviceInstance);

// The paths a NEW set uses (always CARI), whatever is in certDir now.
HubCertPaths CariHubCertPaths(const std::string& certDir, uint32_t deviceInstance);

// `path` relative to `base` with '/' separators, or `path` itself if it isn't
// under `base`. For log lines and the HTTP slot table.
std::string RelativeTo(const std::string& base, const std::string& path);

}  // namespace CertLayout

#endif  // BSCHUB_EXAMPLE_CERT_LAYOUT_H
