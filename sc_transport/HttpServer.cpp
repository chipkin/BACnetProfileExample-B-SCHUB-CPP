// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
// Implementation of HttpServer. See HttpServer.h for the contract and the
// safety reasoning behind every design choice made here.
#include "HttpServer.h"

#include "CASExampleLog.h"

#include <libwebsockets.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace CASSc {

// Upload size bounds (Task 4's "reasonable size bounds" requirement). A real
// certificate/CSR PEM file is a few KB; 64 bytes is comfortably below the
// smallest plausible real cert, 65536 (64 KiB) comfortably above the largest
// plausible one (even a long chain pasted into one slot by mistake) - this is
// a sanity bound, not a precise one; see main() below for the honest
// statement that this is NOT full X.509 validation.
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
    // No TLS - this is plain HTTP. Was acceptable UNCONDITIONALLY when this
    // listener could only ever bind 127.0.0.1; now that --http-bind /
    // config-file http-bind can point it elsewhere, that safety margin is
    // gone the moment an operator opts in - see the loud warning just below
    // and issue #22 for why this would need real TLS
    // (or a unix domain socket / named pipe instead of TCP) to be a sound
    // default off loopback, which this fix does NOT add.
    info.user = this;
    info.gid = static_cast<gid_t>(-1);
    info.uid = static_cast<uid_t>(-1);

    lws_context* ctx = lws_create_context(&info);
    if (ctx == nullptr) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Error,
            "HTTP server: failed to bind %s:%u (port already in use? address not assigned to this host?). "
            "Health/metrics (Task 3) and certificate upload (Task 4) endpoints are NOT available "
            "this run; BACnet/IP and BACnet/SC are unaffected.",
            m_config.bindAddress.c_str(), (unsigned)m_config.port);
        return false;
    }

    m_context = ctx;
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
        "HTTP server: listening on http://%s:%u (GET /health, GET /metrics - no auth; "
        "POST /certs/<slot> - %s)",
        m_config.bindAddress.c_str(), (unsigned)m_config.port,
        m_config.bearerToken.empty() ? "DISABLED, dcc-password not configured" : "requires Authorization: Bearer <dcc-password>");

    // Logged every Start() (not once-ever) so this cannot scroll past an
    // operator who only checks the tail of a long-running log - see
    // HttpServer.h's Start() doc comment for the full reasoning. Deliberately
    // separate from the INFO line above (a Warning-level line an operator's
    // own log filtering is more likely to surface) rather than folded into it.
    if (!isLoopback) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "HTTP server: bound to %s, NOT 127.0.0.1/localhost - GET /health and GET /metrics are now "
            "reachable from off this host with NO authentication and NO TLS, and POST /certs/<slot> "
            "(if enabled) has only a bearer-token check, not a real auth scheme, also over plain HTTP. "
            "This is a deliberate opt-in (--http-bind / config-file http-bind), not this example's "
            "default - see README.md \"Health/metrics HTTP endpoint\" before doing this on a network "
            "you do not fully trust.",
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
    // "accepts with no auth") when dcc-password is unset/empty - see
    // HttpServer.h's class comment and main.cpp's wiring of bearerToken.
    if (m_config.bearerToken.empty()) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "cert upload REJECTED from %s: slot=\"%s\" - upload endpoint is disabled "
            "(dcc-password is not configured; see README.md \"Secrets handling\").",
            peer, session->slot.c_str());
        SendResponse(wsi, session, 503, "text/plain",
                    "certificate upload is disabled: no dcc-password is configured.\n");
        return;
    }
    if (!session->authOk) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "cert upload REJECTED from %s: slot=\"%s\" - missing/invalid bearer token.",
            peer, session->slot.c_str());
        SendResponse(wsi, session, 401, "text/plain",
                    "missing or invalid Authorization: Bearer <dcc-password> header.\n");
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

    // PEM sanity check (Task 4: "looks like a PEM certificate" - deliberately
    // NOT a full X.509 parse. OpenSSL is already vendored for the SC
    // transport's TLS and COULD be used here for a real parse-and-sanity
    // check; this example sticks to a header/size check because (a) it is a
    // small, contained, easy-to-audit amount of code for a tutorial, (b) the
    // real trust decision for an uploaded cert is made by the peer TLS stack
    // at the next handshake anyway - a malformed cert simply fails to work,
    // it does not compromise this device - and (c) adding a full ASN.1/X.509
    // parse here would be exactly the kind of scope creep this batch's task
    // list explicitly asks to weigh carefully. Issue #25 tracks validating
    // uploads the way CertStore validates BACnet writes.
    const bool isCsr = (session->slot == "csr");
    const std::string neededHeader = isCsr ? "-----BEGIN CERTIFICATE REQUEST-----" : "-----BEGIN CERTIFICATE-----";
    if (session->body.find(neededHeader) == std::string::npos) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "cert upload REJECTED from %s: slot=\"%s\" - body does not look like PEM (missing \"%s\").",
            peer, session->slot.c_str(), neededHeader.c_str());
        SendResponse(wsi, session, 400, "text/plain",
                    "upload rejected: does not look like a PEM " + std::string(isCsr ? "CSR" : "certificate") + ".\n");
        return;
    }

    // Write to a temp file, then atomically rename over the live target -
    // peers may be actively reading the live file via AtomicReadFile
    // (main.cpp's CallbackReadFile) mid-upload; a partial/truncated write to
    // the live path would corrupt an in-progress read.
    const std::string targetPath = m_config.certDir + "/" + session->relativeFilename;
    const std::string tmpPath = targetPath + ".upload-tmp";
    {
        std::ofstream tmp(tmpPath, std::ios::binary | std::ios::trunc);
        if (!tmp.is_open()) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                "cert upload FAILED from %s: slot=\"%s\" - could not open temp file \"%s\" for writing.",
                peer, session->slot.c_str(), tmpPath.c_str());
            SendResponse(wsi, session, 500, "text/plain", "upload failed: could not write temp file.\n");
            return;
        }
        tmp.write(session->body.data(), static_cast<std::streamsize>(session->body.size()));
        tmp.close();
        if (!tmp.good()) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                "cert upload FAILED from %s: slot=\"%s\" - write to temp file \"%s\" failed.",
                peer, session->slot.c_str(), tmpPath.c_str());
            std::remove(tmpPath.c_str());
            SendResponse(wsi, session, 500, "text/plain", "upload failed: write error.\n");
            return;
        }
    }

#if defined(_WIN32)
    const bool renamed = MoveFileExA(tmpPath.c_str(), targetPath.c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
#else
    const bool renamed = std::rename(tmpPath.c_str(), targetPath.c_str()) == 0;
#endif
    if (!renamed) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "cert upload FAILED from %s: slot=\"%s\" - could not rename \"%s\" -> \"%s\".",
            peer, session->slot.c_str(), tmpPath.c_str(), targetPath.c_str());
        std::remove(tmpPath.c_str());
        SendResponse(wsi, session, 500, "text/plain", "upload failed: could not replace target file.\n");
        return;
    }

    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
        "cert upload SUCCESS from %s: slot=\"%s\" -> \"%s\" (%zu bytes).",
        peer, session->slot.c_str(), targetPath.c_str(), session->body.size());
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
            session->authOk = !m_config.bearerToken.empty() && presentedToken == m_config.bearerToken;

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
            if (session->tooLarge) {
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
