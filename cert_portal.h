// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CERT_PORTAL_H
#define BSCHUB_EXAMPLE_CERT_PORTAL_H

// cert_portal.h
// =============================================================================
// The certificate set-up guide (issue #72): GET /setup, a page that walks
// someone from "I have a device" to "my device is connected", and the
// /api/... endpoints it calls. Served by sc_transport/HttpServer through its
// route hook.
//
//   GET  /setup                          the guide (one page, no external resources)
//   GET  /api/setup/info                 hub URI(s), the hub's and CA's certificates
//                                        with every field and check, the gate
//   GET  /api/setup/issuer/<file>        iss-1.pem, iss-1.cer, iss-2.pem (public)
//   POST /api/inspect?name=<file>        any file -> what it is, every field, the checks
//   POST /api/check-password             is the password right? (counts as an attempt)
//   POST /api/sign?label=&instance=&port=&name=      PRIVILEGED: sign a CSR or CARI request
//   POST /api/generate?label=&instance=&port=        PRIVILEGED: make a device's key + certificate
//   GET  /api/clients                    the device folders made so far
//   GET  /api/download/<label>/<path>    a file in clients/<label>/ (private ones: PRIVILEGED)
//   GET  /api/cari/<file>                a CARI response made by /api/sign
//   GET  /api/diagnostics?after=<n>      recent connection attempts + connected devices
//   GET  /api/report                     a plain-text diagnostic report for support
//
// THE GATE. Privileged actions need the password of the hub's private key -
// sc-key-password, or the password typed at start-up (KeyPassword), sent as
// "Authorization: HubKey <base64 of the password>":
//   - with a password-protected key: needed from everywhere, loopback too;
//     compared in constant time; 5 wrong tries a minute per address (30 in
//     total) then HTTP 429; never accepted over plain HTTP from another
//     computer (it would cross the network in clear - use --http-tls).
//   - without one (the default lab set): privileged actions only from
//     loopback (127.0.0.1 / ::1), refused from anywhere else.
//   - either way the header must be there ("HubKey -" without a password):
//     another web site's page can't add it without a CORS preflight, which
//     the hub never answers - so a page in the hub computer's browser can't
//     make the hub sign anything (CSRF). Without a password the Host header
//     must also be a loopback name, which stops DNS rebinding.
// Every privileged action is logged (who, what, result).
// =============================================================================

#include <stdint.h>

#include <functional>
#include <string>
#include <vector>

#include "cert_layout.h"
#include "sc_transport/HttpServer.h"

namespace CertPortal {

struct Config {
    std::function<CertLayout::HubCertPaths()> certPaths;
    std::function<std::vector<std::string>()> hubUris;   // what a device should dial
    std::function<std::string()> connectedDevicesJson;   // JSON array, from ScTransport::GetPeers()
    std::function<const char*()> keyPassword;            // nullptr = the hub's key has no password
    std::string appName;
    std::string appVersion;
    std::string stackVersion;
    std::string deviceName;
    uint32_t deviceInstance = 0;
    uint16_t scPort = 0;
};

void Configure(const Config& config);

// The HttpServer route handler for "/setup" and "/api/".
bool HandleRoute(const CASSc::HttpRequest& request, CASSc::HttpResponse* response);

}  // namespace CertPortal

#endif  // BSCHUB_EXAMPLE_CERT_PORTAL_H
