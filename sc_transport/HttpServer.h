// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
#pragma once

// HttpServer.h
// =============================================================================
// A minimal, plain-HTTP (no TLS) server built on the already-vendored
// libwebsockets library (sc_transport/ScTransport.cpp already links it for
// the BACnet/SC WebSocket+TLS transport - see that file's header) - added
// this batch for:
//
//   Task 3: GET /health and GET /metrics - a read-only JSON snapshot of the
//           same data the 'm' keypress prints (uptime, BACnet/SC connection
//           count vs --sc-max-hub-connections, connect/disconnect/rate-limit
//           counters, RX/TX counters). No authentication - see the class
//           comment below for why that is an accepted, documented tradeoff
//           for THIS endpoint specifically.
//
//   Task 4: POST /certs/<slot> - uploads a replacement certificate/CSR file
//           into --sc-cert-dir (the same directory main.cpp's
//           CallbackReadFile already serves File-object bytes from). This is
//           the highest-risk addition in this batch - see its own comment
//           block below (HttpServer::Start) for the full safety reasoning.
//
// WHY ONE SEPARATE lws_context, NOT A SHARED ONE WITH ScTransport'S LISTENER.
// ScTransport's listener context is TLS 1.3 + mutual-client-cert, speaks the
// "hub.bsc.bacnet.org" WebSocket subprotocol, and its per-connection state
// (PeerConnection) is BACnet/SC-specific. This HTTP server is plain HTTP
// (no TLS - see Start()'s own comment on why 127.0.0.1-only makes that an
// acceptable tutorial tradeoff), a completely different protocol handler
// (LWS_CALLBACK_HTTP/_BODY/_BODY_COMPLETION/_WRITEABLE, not the WebSocket
// RECEIVE/WRITEABLE reasons ScTransport handles), and deliberately isolated
// from the BACnet/SC transport's own state so a bug in one cannot corrupt
// the other. Reusing lws (not adding a second HTTP library / a new vcpkg
// dependency) is the whole point of building this on top of libwebsockets;
// reusing the SAME lws_context/vhost as the SC listener is not required to
// get that benefit and would tangle two very different protocol handlers
// together for no real gain - see docs/bacnet-sc-transport-plan.md's general
// preference for "reuse the mechanism, keep the roles separate" (the
// listener/connector split in ScTransport itself is the same pattern).
//
// GET vs POST ISOLATION (explicitly required by this batch's Task 4): GET
// /health and GET /metrics never check the bearer token (Task 3 is
// deliberately unauthenticated - read-only, low-risk, and a tutorial
// monitoring integration should not need a secret just to poll uptime).
// POST /certs/<slot> ALWAYS requires it (and is disabled outright if no
// dcc-password is configured - see Start()'s comment). HandleHttp() below
// keeps this a hard branch on HTTP method, not a shared code path, precisely
// so a bug cannot accidentally let the auth requirement leak from one route
// to the other in either direction.
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>

struct lws_context;
struct lws;
struct lws_protocols;

namespace CASSc {

// One entry in the cert-upload slot table: POST /certs/<slot> maps `slot`
// (e.g. "operational", "csr", "issuer1", "issuer2") to the relative filename
// under --sc-cert-dir it overwrites. Supplied by main.cpp (not hard-coded
// here) so this class does not duplicate main.cpp's own File-object-instance
// -> filename mapping (ScCertFileRelativePath) - single source of truth.
using CertSlotResolver = std::function<bool(const std::string& slot, std::string* outRelativeFilename)>;

// Supplies the JSON body for GET /health and GET /metrics - the SAME data
// (uptime, connection counts, RX/TX counters) the 'm' keypress prints, built
// by the same function in main.cpp so the two can never drift apart.
using HealthJsonBuilder = std::function<std::string()>;

struct HttpServerConfig {
    uint16_t port = 0;             // TCP port to bind (127.0.0.1 only - see Start())
    std::string certDir;           // --sc-cert-dir - where an accepted upload is written
    std::string bearerToken;       // dcc-password (Task 1's config-file-only setting).
                                    // EMPTY means the upload endpoint is DISABLED entirely
                                    // (see Start()'s comment) - GET /health and GET /metrics
                                    // are unaffected either way.
    CertSlotResolver resolveCertSlot;
    HealthJsonBuilder buildHealthJson;
};

class HttpServer {
public:
    HttpServer();
    ~HttpServer();

    // Starts listening on 127.0.0.1:config.port. ALWAYS binds 127.0.0.1
    // specifically (never 0.0.0.0/an empty iface) - this is a tutorial
    // default, not a policy switch: there is no --http-bind-address option
    // in this batch, deliberately, so a config file cannot accidentally
    // expose this endpoint (particularly the upload one) to the network by
    // omission - see TODO.md "Genuinely open items" for what a real product
    // would need instead (TLS on this listener, a real auth scheme, a bind
    // address that is an explicit, reviewed decision rather than a default).
    // Returns false (logs) if the bind fails - NOT fatal to the rest of the
    // program (main.cpp keeps running with this endpoint simply absent) so a
    // busy --http-port does not take down BACnet/SC or BACnet/IP.
    bool Start(const HttpServerConfig& config);

    void Stop();
    bool IsRunning() const { return m_context != nullptr; }

    // Pumps the HTTP lws_context non-blockingly - same `lws_cancel_service` +
    // `lws_service(ctx, 0)` mechanism ScTransport::Service() already uses.
    // Call once per main-loop tick, alongside g_scTransport.Service().
    void Service();

    // lws callback trampoline entry point - public only because it must be
    // reachable from a free C function pointer (struct lws_protocols::callback);
    // not meant to be called by application code. See HttpServer.cpp.
    int HandleHttp(lws* wsi, int reason, void* in, std::size_t len);

private:
    struct Session;  // defined in HttpServer.cpp - holds std::string members,
                      // so (like ScTransport's PeerConnection/ClientConnection)
                      // it lives in a std::map keyed by wsi*, not in lws's own
                      // raw-zalloc'd per-session-data block.

    void HandleGet(lws* wsi, Session* session);
    void HandlePostBodyComplete(lws* wsi, Session* session);
    void SendResponse(lws* wsi, Session* session, int statusCode, const std::string& contentType,
                      const std::string& body);

    HttpServerConfig m_config;
    lws_context* m_context = nullptr;
    struct lws_protocols* m_protocols = nullptr;  // heap-allocated, same reason as ScTransport's m_protocols

    std::map<lws*, Session*> m_sessions;
};

}  // namespace CASSc
