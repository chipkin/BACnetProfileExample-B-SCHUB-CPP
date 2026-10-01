// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// ScDiagnostics.h - the last BACnet/SC connection events, for the set-up
// guide's "test the connection" panel (issue #72).
//
// The log already says why a device was refused, but someone setting up a
// device needs it next to the files they just made, in plain language. So the
// transport also records each step of a connection attempt here, in a small
// process-wide ring buffer, and GET /api/diagnostics returns it:
//
//   tcp            a TCP connection arrived (address) - the attempt started
//   rate-limited   refused before TLS (--sc-rate-limit)
//   tls-refused    the device's certificate failed verification (OpenSSL's
//                  reason, the certificate's subject and issuer)
//   subprotocol    the WebSocket upgrade asked for the wrong subprotocol
//   connected      TLS and WebSocket done (address, certificate subject)
//   accepted       the hub accepted its Connect-Request (VMAC, UUID)
//   refused        the hub refused its Connect-Request (the stack's reason)
//   disconnected   the connection closed (close code)
//   connector      the hub's own connection out (--sc-hub-uri) failed
//
// A "tcp" with nothing after it means the TLS handshake failed before the hub
// could look at a certificate: no client certificate, TLS 1.2 only, or the
// device refusing the HUB's certificate (it doesn't trust iss-1.pem). No
// secrets are recorded - only names, addresses and reasons.
//
// The verify callback has no connection to attach to (lws gives it no wsi),
// which is why this is process-wide rather than per connection: events are in
// time order, and the panel reads them as a timeline.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace CASSc {
namespace ScDiagnostics {

struct Event {
    uint64_t sequence = 0;      // increases by one per event, for "what's new since"
    std::string time;           // UTC, "2026-10-01T12:00:00Z"
    std::string kind;           // see the list above
    std::string address;        // "10.0.0.31:64150" when known
    std::string subject;        // the certificate subject, when known
    std::string issuer;         // the certificate's issuer, when known
    std::string detail;         // the reason / VMAC and UUID / close code
};

// Adds an event (oldest dropped beyond kMaxEvents). Thread-safe.
void Record(const std::string& kind, const std::string& address, const std::string& subject,
            const std::string& issuer, const std::string& detail);

// Every kept event with sequence > `after`, oldest first.
std::vector<Event> Since(uint64_t after);

const unsigned kMaxEvents = 100;

}  // namespace ScDiagnostics
}  // namespace CASSc
