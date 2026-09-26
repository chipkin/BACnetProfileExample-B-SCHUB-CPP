// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
// Implementation of HttpServer. See HttpServer.h for the contract and the
// safety reasoning behind every design choice made here.
#include "HttpServer.h"

#include "CASExampleLog.h"

#include <libwebsockets.h>
#include <openssl/crypto.h>  // CRYPTO_memcmp - SecretsEqual()
#include <openssl/evp.h>     // SHA-256 - SecretsEqual()
#include <openssl/ssl.h>     // SSL_OP_NO_* - HTTPS protocol versions

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>

namespace CASSc {

// Upload size bounds (Task 4's "reasonable size bounds" requirement). A real
// certificate/CSR PEM file is a few KB; 64 bytes is comfortably below the
// smallest plausible real cert, 65536 (64 KiB) comfortably above the largest
// plausible one (even a long chain pasted into one slot by mistake) - this is
// a sanity bound, not a precise one - the real validation is main.cpp's
// ApplyCertUpload (issue #25).
const size_t kMinUploadBytes = 64;
const size_t kMaxUploadBytes = 65536;

// The Session type HttpServer.h forward-declares. Lives in a std::map keyed
// by wsi* (same pattern as ScTransport::PeerConnection/ClientConnection) so
// it can hold std::string members - lws's own per_session_data_size block is
// raw zalloc'd memory with no constructor call, which std::string cannot
// safely live in.
struct HttpServer::Session {
    bool isPost = false;
    std::string uri;

    // Resolved once, at LWS_CALLBACK_HTTP time (POST only) - BEFORE the body
    // is read - so the auth/slot verdict cannot be influenced by anything in
    // the body itself, and so a rejection is known even if the body never
    // finishes uploading.
    bool authOk = false;
    bool slotKnown = false;
    std::string relativeFilename;  // under certDir, from resolveCertSlot()
    std::string slot;              // raw slot name, for logging

    bool rateLimited = false;          // refused by AllowUploadAttempt() (issue #24)
    const char* rateLimitWhich = "";

    bool tooLarge = false;   // Content-Length header (or accumulated body) exceeded kMaxUploadBytes
    std::string body;        // accumulated POST body (empty/ignored once tooLarge)

    std::string response;    // body of the HTTP response, once decided
    size_t responseSent = 0;
    bool headersWritten = false;

    void Reset() {
        isPost = false;
        uri.clear();
        authOk = false;
        slotKnown = false;
        relativeFilename.clear();
        slot.clear();
        rateLimited = false;
        rateLimitWhich = "";
        tooLarge = false;
        body.clear();
        response.clear();
        responseSent = 0;
        headersWritten = false;
    }
};

namespace {

int LwsHttpCallbackTrampoline(lws* wsi, lws_callback_reasons reason, void* user, void* in, std::size_t len) {
    (void)user;
    lws_context* ctx = wsi != nullptr ? lws_get_context(wsi) : nullptr;
    if (ctx == nullptr) {
        return 0;
    }
    HttpServer* self = static_cast<HttpServer*>(lws_context_user(ctx));
    if (self == nullptr) {
        return 0;
    }
    return self->HandleHttp(wsi, static_cast<int>(reason), in, len);
}

}  // namespace

bool SecretsEqual(const std::string& presented, const std::string& expected) {
    unsigned char presentedDigest[EVP_MAX_MD_SIZE];
    unsigned char expectedDigest[EVP_MAX_MD_SIZE];
    unsigned int presentedLen = 0;
    unsigned int expectedLen = 0;
    if (EVP_Digest(presented.data(), presented.size(), presentedDigest, &presentedLen, EVP_sha256(), nullptr) != 1 ||
        EVP_Digest(expected.data(), expected.size(), expectedDigest, &expectedLen, EVP_sha256(), nullptr) != 1 ||
        presentedLen != expectedLen) {
        return false;
    }
    return CRYPTO_memcmp(presentedDigest, expectedDigest, presentedLen) == 0;
}

// Refills a bucket holding at most `capacity` tokens at `capacity` per minute,
// then takes one token if there is one. A bucket never used before starts full.
static bool TakeAttempt(double* tokens, std::chrono::steady_clock::time_point* lastRefill, const unsigned capacity,
                        const std::chrono::steady_clock::time_point now) {
    if (*lastRefill == std::chrono::steady_clock::time_point()) {
        *tokens = capacity;
    } else {
        const double perSecond = capacity / 60.0;
        const double refilled = *tokens + std::chrono::duration<double>(now - *lastRefill).count() * perSecond;
        *tokens = (refilled < capacity) ? refilled : capacity;  // not std::min - <windows.h> min/max macros
    }
    *lastRefill = now;
    if (*tokens >= 1.0) {
        *tokens -= 1.0;
        return true;
    }
    return false;
}

bool HttpServer::AllowUploadAttempt(const std::string& client, const char** which) {
    const auto now = std::chrono::steady_clock::now();
    // Bounded table: forget clients whose bucket has had a minute to refill
    // (a new bucket starts full, so nothing is lost). If every tracked client
    // is recent, the total limit alone applies to a new one.
    const size_t kMaxTrackedClients = 256;
    auto it = m_uploadByClient.find(client);
    if (it == m_uploadByClient.end() && m_uploadByClient.size() >= kMaxTrackedClients) {
        for (auto c = m_uploadByClient.begin(); c != m_uploadByClient.end();) {
            c = (now - c->second.lastRefill >= std::chrono::minutes(1)) ? m_uploadByClient.erase(c) : std::next(c);
        }
    }
    if (it == m_uploadByClient.end() && m_uploadByClient.size() < kMaxTrackedClients) {
        it = m_uploadByClient.emplace(client, AttemptBucket()).first;
    }
    if (it != m_uploadByClient.end() &&
        !TakeAttempt(&it->second.tokens, &it->second.lastRefill, kUploadAttemptsPerClient, now)) {
        *which = "per-client";
        return false;
    }
    if (!TakeAttempt(&m_uploadTotal.tokens, &m_uploadTotal.lastRefill, kUploadAttemptsTotal, now)) {
        *which = "total";
        return false;
    }
    return true;
}

HttpServer::HttpServer() {}

HttpServer::~HttpServer() {
    Stop();
}

bool HttpServer::Start(const HttpServerConfig& config) {
    Stop();
    m_config = config;

    delete[] m_protocols;
    m_protocols = new lws_protocols[2];
    std::memset(m_protocols, 0, sizeof(lws_protocols) * 2);
    m_protocols[0].name = "http";
    m_protocols[0].callback = &LwsHttpCallbackTrampoline;
    m_protocols[0].per_session_data_size = 0;  // per-connection state lives in m_sessions, keyed by wsi*
    m_protocols[0].rx_buffer_size = 4096;

    if (m_config.bindAddress.empty()) {
        m_config.bindAddress = "127.0.0.1";  // same default as main.cpp's g_httpBindAddress - belt and suspenders
    }
    const bool isLoopback = (m_config.bindAddress == "127.0.0.1" || m_config.bindAddress == "localhost");

    lws_context_creation_info info;
    std::memset(&info, 0, sizeof(info));
    info.port = m_config.port;
    info.iface = m_config.bindAddress.c_str();
    info.protocols = m_protocols;
    // HTTPS when a certificate is configured (issue #22), plain HTTP otherwise.
    // TLS 1.2 or 1.3 (browsers and curl, not BACnet/SC peers, connect here).
    // The process already keeps a TLS lws_context alive for its whole life
    // (ScTransport's EnsureTlsLifetimeContext), so creating/destroying this one
    // is safe.
    const bool useTls = !m_config.tlsCertPath.empty();
    if (useTls) {
        info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
        info.ssl_cert_filepath = m_config.tlsCertPath.c_str();
        info.ssl_private_key_filepath = m_config.tlsKeyPath.c_str();
        info.ssl_options_set = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
    }
    info.user = this;
    info.gid = static_cast<gid_t>(-1);
    info.uid = static_cast<uid_t>(-1);

    lws_context* ctx = lws_create_context(&info);
    if (ctx == nullptr) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Error,
            "HTTP server: failed to start on %s:%u (port already in use? address not assigned to this host?%s). "
            "Health/metrics (Task 3) and certificate upload (Task 4) endpoints are NOT available "
            "this run; BACnet/IP and BACnet/SC are unaffected.",
            m_config.bindAddress.c_str(), (unsigned)m_config.port,
            useTls ? " HTTPS certificate or key unreadable?" : "");
        return false;
    }

    m_context = ctx;
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
        "HTTP server: listening on %s://%s:%u (GET /health, GET /metrics - no auth; "
        "POST /certs/<slot> - %s)",
        useTls ? "https" : "http", m_config.bindAddress.c_str(), (unsigned)m_config.port,
        m_config.bearerToken.empty() ? "DISABLED, http-upload-token not configured"
                                     : "requires Authorization: Bearer <http-upload-token>");

    // Logged every Start() (not once-ever) so this cannot scroll past an
    // operator who only checks the tail of a long-running log - see
    // HttpServer.h's Start() doc comment for the full reasoning. Deliberately
    // separate from the INFO line above (a Warning-level line an operator's
    // own log filtering is more likely to surface) rather than folded into it.
    if (!isLoopback && !useTls) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "HTTP server: bound to %s, NOT 127.0.0.1/localhost, over PLAIN HTTP - GET /, /health and /metrics "
            "(no authentication) and the POST /certs/<slot> bearer token travel unencrypted. Turn on "
            "--http-tls, or use an SSH tunnel or a TLS reverse proxy - see docs/manual.md \"Security\".",
            m_config.bindAddress.c_str());
    } else if (!isLoopback) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
            "HTTP server: bound to %s over HTTPS - GET /, /health and /metrics need no authentication; "
            "anyone who can reach this address can read them.",
            m_config.bindAddress.c_str());
    }
    return true;
}

void HttpServer::Stop() {
    if (m_context != nullptr) {
        lws_context_destroy(m_context);
        m_context = nullptr;
    }
    for (auto& kv : m_sessions) {
        delete kv.second;
    }
    m_sessions.clear();
    delete[] m_protocols;
    m_protocols = nullptr;
}

void HttpServer::Service() {
    if (m_context == nullptr) {
        return;
    }
    lws_cancel_service(m_context);
    lws_service(m_context, 0);
}

void HttpServer::SendResponse(lws* wsi, Session* session, const int statusCode,
                              const std::string& contentType, const std::string& body) {
    uint8_t buf[LWS_PRE + 1024];
    uint8_t* start = &buf[LWS_PRE];
    uint8_t* p = start;
    uint8_t* end = &buf[sizeof(buf) - 1];

    lws_add_http_common_headers(wsi, static_cast<unsigned int>(statusCode), contentType.c_str(),
                                static_cast<lws_filepos_t>(body.size()), &p, end);
    // Force a fresh connection per request (no HTTP keep-alive) - simpler and
    // safer for a tutorial server that does not otherwise reset session
    // state defensively between requests on a reused socket.
    unsigned char connectionClose[] = "close";
    lws_add_http_header_by_name(wsi, reinterpret_cast<const unsigned char*>("connection:"),
                                connectionClose, 5, &p, end);
    lws_finalize_write_http_header(wsi, start, &p, end);

    session->response = body;
    session->responseSent = 0;
    session->headersWritten = true;
    lws_callback_on_writable(wsi);
}

void HttpServer::HandleGet(lws* wsi, Session* session) {
    // GET / - the status page for a person with a browser. Same data as
    // /health and /metrics (no authentication either), plus version numbers.
    if (session->uri == "/" && m_config.buildStatusPage) {
        SendResponse(wsi, session, 200, "text/html; charset=utf-8", m_config.buildStatusPage());
        return;
    }
    if (session->uri == "/health") {
        bool healthy = true;
        const std::string json = m_config.buildHealthJson ? m_config.buildHealthJson(&healthy) : std::string("{}");
        SendResponse(wsi, session, healthy ? 200 : 503, "application/json", json);
        return;
    }
    if (session->uri == "/metrics") {
        const std::string json = m_config.buildMetricsJson ? m_config.buildMetricsJson() : std::string("{}");
        SendResponse(wsi, session, 200, "application/json", json);
        return;
    }
    SendResponse(wsi, session, 404, "text/plain",
                "not found. Try GET /, GET /health, GET /metrics, or POST /certs/<slot>.\n");
}

void HttpServer::HandlePostBodyComplete(lws* wsi, Session* session) {
    char peer[128] = {0};
    lws_get_peer_simple(wsi, peer, sizeof(peer));

    // Task 4 safety requirement: the endpoint is DISABLED ENTIRELY (not
    // "accepts with no auth") when http-upload-token is unset/empty - see
    // HttpServer.h's class comment and main.cpp's wiring of bearerToken.
    if (m_config.bearerToken.empty()) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "cert upload REJECTED from %s: slot=\"%s\" - upload endpoint is disabled "
            "(http-upload-token is not configured).",
            peer, session->slot.c_str());
        SendResponse(wsi, session, 503, "text/plain",
                    "certificate upload is disabled: no http-upload-token is configured.\n");
        return;
    }
    // Too many attempts (issue #24) - checked before the token, so a guesser
    // learns nothing from a refused attempt.
    if (session->rateLimited) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "cert upload REFUSED from %s: slot=\"%s\" - %s limit reached (%u attempts a minute per client, "
            "%u in total)", peer, session->slot.c_str(), session->rateLimitWhich, kUploadAttemptsPerClient,
            kUploadAttemptsTotal);
        SendResponse(wsi, session, 429, "text/plain", "too many upload attempts; try again in a minute.\n");
        return;
    }
    if (!session->authOk) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "cert upload REJECTED from %s: slot=\"%s\" - missing/invalid bearer token.",
            peer, session->slot.c_str());
        SendResponse(wsi, session, 401, "text/plain",
                    "missing or invalid Authorization: Bearer <http-upload-token> header.\n");
        return;
    }
    if (!session->slotKnown) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "cert upload REJECTED from %s: unknown slot \"%s\" (uri \"%s\").",
            peer, session->slot.c_str(), session->uri.c_str());
        SendResponse(wsi, session, 404, "text/plain", "unknown certificate slot.\n");
        return;
    }
    if (session->tooLarge || session->body.size() < kMinUploadBytes || session->body.size() > kMaxUploadBytes) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "cert upload REJECTED from %s: slot=\"%s\" - size %zu bytes out of bounds (%zu..%zu).",
            peer, session->slot.c_str(), session->body.size(), kMinUploadBytes, kMaxUploadBytes);
        SendResponse(wsi, session, 413, "text/plain", "upload rejected: size out of bounds.\n");
        return;
    }

    // Validate and install it (issue #25): main.cpp's handler runs the upload
    // through the same checks as a certificate written over BACnet - it must
    // parse as X.509, and the resulting set must still let the hub run
    // BACnet/SC (the operational certificate matches the private key and
    // chains to an issuer) - before anything reaches disk.
    std::string message;
    const int status = m_config.applyCertUpload
        ? m_config.applyCertUpload(session->slot, session->body, &message)
        : 503;
    if (status != 200) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "cert upload REJECTED from %s: slot=\"%s\" (%zu bytes) - %s",
            peer, session->slot.c_str(), session->body.size(), message.c_str());
        SendResponse(wsi, session, status, "text/plain", "upload rejected: " + message + "\n");
        return;
    }
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
        "cert upload SUCCESS from %s: slot=\"%s\" (%zu bytes) - %s",
        peer, session->slot.c_str(), session->body.size(), message.c_str());
    SendResponse(wsi, session, 200, "application/json",
                "{\"status\":\"ok\",\"slot\":\"" + session->slot + "\",\"bytes\":" +
                std::to_string(session->body.size()) + "}");
}

int HttpServer::HandleHttp(lws* wsi, const int reasonInt, void* in, const std::size_t len) {
    const lws_callback_reasons reason = static_cast<lws_callback_reasons>(reasonInt);

    switch (reason) {
        case LWS_CALLBACK_HTTP: {
            Session* session = nullptr;
            auto it = m_sessions.find(wsi);
            if (it == m_sessions.end()) {
                session = new Session();
                m_sessions[wsi] = session;
            } else {
                session = it->second;
                session->Reset();  // HTTP keep-alive reusing this wsi for a new request
            }

            session->uri.assign(static_cast<const char*>(in), len);

            const bool isPost = lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI) > 0;
            session->isPost = isPost;

            if (!isPost) {
                HandleGet(wsi, session);
                return 0;
            }

            // Count the attempt (issue #24) - every POST, before anything else.
            {
                char client[128] = {0};
                lws_get_peer_simple(wsi, client, sizeof(client));
                session->rateLimited = !AllowUploadAttempt(client, &session->rateLimitWhich);
            }

            // POST /certs/<slot> - resolve auth + slot NOW, before any body
            // byte is read (Task 4 safety requirement: reject before
            // touching disk). See Session::authOk's comment.
            char authHeader[512] = {0};
            lws_hdr_copy(wsi, authHeader, static_cast<int>(sizeof(authHeader)), WSI_TOKEN_HTTP_AUTHORIZATION);
            static const char kBearerPrefix[] = "Bearer ";
            const size_t prefixLen = sizeof(kBearerPrefix) - 1;
            std::string presentedToken;
            if (std::strncmp(authHeader, kBearerPrefix, prefixLen) == 0) {
                presentedToken = std::string(authHeader + prefixLen);
            }
            session->authOk = !m_config.bearerToken.empty() && SecretsEqual(presentedToken, m_config.bearerToken);

            static const char kCertsPrefix[] = "/certs/";
            if (session->uri.compare(0, sizeof(kCertsPrefix) - 1, kCertsPrefix) == 0) {
                session->slot = session->uri.substr(sizeof(kCertsPrefix) - 1);
            }
            std::string relativeFilename;
            if (m_config.resolveCertSlot && !session->slot.empty() &&
                m_config.resolveCertSlot(session->slot, &relativeFilename)) {
                session->slotKnown = true;
                session->relativeFilename = relativeFilename;
            }

            // Reject an early-declared oversized body without bothering to
            // buffer it - lws still delivers the BODY chunks (we just ignore
            // them, see LWS_CALLBACK_HTTP_BODY below).
            char contentLenStr[32] = {0};
            lws_hdr_copy(wsi, contentLenStr, static_cast<int>(sizeof(contentLenStr)), WSI_TOKEN_HTTP_CONTENT_LENGTH);
            if (contentLenStr[0] != '\0') {
                const long contentLen = std::strtol(contentLenStr, nullptr, 10);
                if (contentLen < 0 || static_cast<size_t>(contentLen) > kMaxUploadBytes) {
                    session->tooLarge = true;
                }
            }
            return 0;
        }

        case LWS_CALLBACK_HTTP_BODY: {
            auto it = m_sessions.find(wsi);
            if (it == m_sessions.end()) {
                break;
            }
            Session* session = it->second;
            if (session->tooLarge || session->rateLimited) {
                break;  // already known to be rejected - discard rather than buffer
            }
            session->body.append(static_cast<const char*>(in), len);
            if (session->body.size() > kMaxUploadBytes) {
                session->tooLarge = true;
                session->body.clear();  // release the memory now; response decided at BODY_COMPLETION
            }
            break;
        }

        case LWS_CALLBACK_HTTP_BODY_COMPLETION: {
            auto it = m_sessions.find(wsi);
            if (it == m_sessions.end()) {
                break;
            }
            HandlePostBodyComplete(wsi, it->second);
            break;
        }

        case LWS_CALLBACK_HTTP_WRITEABLE: {
            auto it = m_sessions.find(wsi);
            if (it == m_sessions.end() || !it->second->headersWritten) {
                break;
            }
            Session* session = it->second;
            const size_t remaining = session->response.size() - session->responseSent;
            if (remaining == 0) {
                if (lws_http_transaction_completed(wsi)) {
                    return -1;
                }
                break;
            }
            const int written = lws_write(
                wsi, reinterpret_cast<unsigned char*>(&session->response[session->responseSent]),
                remaining, LWS_WRITE_HTTP);
            if (written < 0) {
                return -1;
            }
            session->responseSent += static_cast<size_t>(written);
            if (session->responseSent < session->response.size()) {
                lws_callback_on_writable(wsi);
            } else if (lws_http_transaction_completed(wsi)) {
                return -1;
            }
            break;
        }

        case LWS_CALLBACK_CLOSED_HTTP: {
            auto it = m_sessions.find(wsi);
            if (it != m_sessions.end()) {
                delete it->second;
                m_sessions.erase(it);
            }
            break;
        }

        default:
            break;
    }
    return 0;
}

}  // namespace CASSc
