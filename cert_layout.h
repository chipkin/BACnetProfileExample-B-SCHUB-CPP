// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CERT_LAYOUT_H
#define BSCHUB_EXAMPLE_CERT_LAYOUT_H

// cert_layout.h
// =============================================================================
// Where the hub's certificate files are in --sc-cert-dir. The ONE place that
// knows the file names; everything else asks ResolveHubCertPaths().
//
// The folder is a CARI tree (Certificate Authority Requirements Interchange,
// ANSI/ASHRAE 135-2024 Annex AA.2, Addendum cs to 135-2020) for the hub
// itself:
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
//     key-hub-pending.pem                  GENERATE_CSR_FILE's new key, until activated
//     trusted-issuers.pem                  written by the hub at start-up (every issuer it trusts)
//     issuer-crl.pem                       optional certificate revocation list(s) from the CA
//     hub-cari-request.zip                 written by --generate-csr, for the CA
//     ca/, clients/                        the demo set only (tools/make_test_certs.py): its
//                                          CA and one CARI response zip per device - the hub
//                                          never reads them
// =============================================================================

#include <stdint.h>

#include <string>

namespace CertLayout {

// The CARI port folder the hub uses for itself: Network Port 2 "BACnet SC".
static const char* const HUB_PORT_ID = "2";
// The <string> in the hub's own csr-/opr-/key- file names.
static const char* const HUB_FILE_NAME = "hub";

struct HubCertPaths {
    std::string certDir;
    // The port folder in use (relative to certDir), e.g.
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
    std::string trustedIssuers;          // written by the hub at start-up
    std::string revocationList;          // issuer-crl.pem (optional, from the site's CA)
};

// Works out the paths in certDir. `deviceInstance` names the CARI device
// folder for a new set; an existing CARI tree is found by looking for
// cert1/device-*/port-*/hub/, so a tree made for another device instance is
// still used (with a note).
HubCertPaths ResolveHubCertPaths(const std::string& certDir, uint32_t deviceInstance);

// `path` relative to `base` with '/' separators, or `path` itself if it isn't
// under `base`. For messages.
std::string RelativeTo(const std::string& base, const std::string& path);

}  // namespace CertLayout

#endif  // BSCHUB_EXAMPLE_CERT_LAYOUT_H
