// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CERT_TOOL_H
#define BSCHUB_EXAMPLE_CERT_TOOL_H

// cert_tool.h
// =============================================================================
// Lab certificates for this example's BACnet/SC hub, built into the executable
// (OpenSSL is already linked for the SC transport), so a user needs no
// separate `openssl` binary. Every file is laid out as CARI (ANSI/ASHRAE
// 135-2024 Annex AA.2; see cari.h and cert_layout.h):
//
//   --generate-certs [n]      A fresh set in --sc-cert-dir: a lab CA (ca/),
//                             the hub's own CARI tree (cert1/...: opr-, key-,
//                             csr-hub.pem and issuer/iss-1.pem) and n device
//                             folders (default 3).
//   --add-client-certs [n]    n MORE devices (default 1), signed by the CA
//                             ALREADY in --sc-cert-dir, so the running hub
//                             trusts them. Numbering continues.
//   --generate-csr            A key and a CARI request for ONE device. Needs no
//                             CA, so a device's owner can run it themselves.
//   --sign-csr <file>         Sign with the existing CA: a CARI request zip
//                             (gives <name>-response.zip next to it), a bare
//                             CSR (PEM or DER; gives clients/<label>/), or a
//                             --generate-csr folder (signed in place).
//   --migrate-certs           Copy an older flat-named folder into a CARI tree.
//   --cert-label <label>      Folder name (prefix for --generate-certs /
//                             --add-client-certs). Default client-NN.
//   --cert-device-instance <n>, --cert-port-id <id>
//                             The device-<n>/port-<id> CARI folder names for a
//                             device (default: the client number, and 1).
//
// Each device folder clients/<label>/ holds that device's CARI response
// (cert1/device-<n>/port-<id>/{csr,opr,key}-<label>.pem, cert1/issuer/iss-1.pem),
// the same tree zipped (<label>-cari-response.zip), and tool files outside
// cert1/: bacnetsc.config (CAS BACnet Explorer), <label>.pfx + iss-1.cer +
// yabe-bacnetsc.config (YABE / Windows), readme.txt.
//
// Certificates: ECDSA P-256, SHA-256; CA 10 years, others 825 days. Hub: EKU
// serverAuth+clientAuth, SAN localhost/127.0.0.1/<hostname>/<hub URI host>.
// Devices: EKU clientAuth, plus serverAuth for a CARI port marked hub/.
// A signed certificate keeps its CSR's subject and public key; nothing else
// from the CSR is copied.
//
// LAB TESTING ONLY. A real deployment uses its own PKI - see
// docs/production-certificates.md.
// =============================================================================

#include <stdint.h>

#include <string>
#include <vector>

#include "cari.h"
#include "cert_layout.h"

namespace CertTool {

static const unsigned DEFAULT_GENERATE_CLIENT_COUNT = 3;
static const unsigned DEFAULT_ADD_CLIENT_COUNT = 1;
static const char* const DEFAULT_CLIENT_LABEL = "client";
static const char* const DEFAULT_CLIENT_PORT_ID = "1";

// Files in a device folder, outside its cert1/ tree.
static const char* const CLIENTS_DIR = "clients";
static const char* const BACNETSC_CONFIG_FILE = "bacnetsc.config";
static const char* const CLIENT_PFX_EXTENSION = ".pfx";
static const char* const ISSUER_CERTIFICATE_DER_FILE = "iss-1.cer";
static const char* const YABE_CONFIG_FILE = "yabe-bacnetsc.config";

// Which device folder(s) to make, and how to name them.
struct ClientOptions {
    std::string label;              // exact folder name; "" = the next client-NN
    std::string labelPrefix = DEFAULT_CLIENT_LABEL;  // for numbered folders
    int64_t deviceInstance = -1;    // device-<n>; -1 = the client number (or 1)
    std::string portId = DEFAULT_CLIENT_PORT_ID;     // port-<id>
    std::string hubUri;             // written into bacnetsc.config
};

// One CSR's result when a CARI request is signed.
struct SignedItem {
    std::string where;          // "device-12/port-1/csr-ahu.pem"
    bool signedOk = false;
    std::string error;          // why it was refused
    std::string subject;
    std::string serial;
    std::string notAfter;
    std::string fingerprint;    // SHA-256
    bool isHubPort = false;
};

// --- command-line modes (print what they do; return true on success) -----------

bool GenerateCertificateSet(const std::string& certDir, uint32_t hubDeviceInstance, unsigned clientCount,
                            const ClientOptions& clients, bool force);
bool AddClientCertificates(const std::string& certDir, uint32_t hubDeviceInstance, unsigned clientCount,
                           const ClientOptions& clients);
bool GenerateClientCsr(const std::string& certDir, const ClientOptions& client);
bool SignClientCsr(const std::string& certDir, uint32_t hubDeviceInstance, const std::string& input,
                   const ClientOptions& client);
bool MigrateCertificates(const std::string& certDir, uint32_t hubDeviceInstance);

// --- building blocks shared with the web set-up guide ---------------------------

// Signs every CSR in `request` (a CARI request) with the hub's CA and builds
// the CARI response: every request file, opr-<name>.pem next to each CSR it
// signed, issuer/iss-1.pem (+ iss-2.pem: the hub's issuers), errors.txt for
// the refused ones, and response-notes.txt. False (with *error) only when
// nothing can be signed at all - no CA, a CA the hub doesn't trust, or a tree
// that isn't CARI; a refused CSR is an item with signedOk = false.
bool SignCariTree(const CertLayout::HubCertPaths& paths, const Cari::Tree& request, Cari::Tree* response,
                  std::vector<SignedItem>* items, std::string* error);

// Makes a device's key, CSR and certificate (signed by the hub's CA) and
// writes its whole folder, clients/<label>/. *folder is set to it.
bool IssueClientFolder(const CertLayout::HubCertPaths& paths, const ClientOptions& client, std::string* folder,
                       std::vector<SignedItem>* items, std::string* error);

// Writes a signed CARI response for ONE device into clients/<label>/ with the
// tool files (bacnetsc.config, and the .pfx/YABE files when the tree holds
// the device's key). *folder is set to it.
bool WriteClientFolder(const CertLayout::HubCertPaths& paths, const std::string& label, const Cari::Tree& response,
                       const std::string& hubUri, std::string* folder, std::string* error);

// A CARI request with one CSR (PEM or DER bytes) at
// cert1/device-<n>/port-<id>/csr-<label>.pem.
bool BareCsrToRequest(const std::string& csrBytes, const ClientOptions& client, const std::string& label,
                      Cari::Tree* request, std::string* error);

// The label --sign-csr/--generate-csr/the web guide would use: client.label,
// or the next free client-NN.
std::string NextClientLabel(const std::string& certDir, const ClientOptions& client);

// True if `label` may name a device folder (letters, digits, '-', '_', '.').
bool IsValidLabel(const std::string& label);

}  // namespace CertTool

#endif  // BSCHUB_EXAMPLE_CERT_TOOL_H
