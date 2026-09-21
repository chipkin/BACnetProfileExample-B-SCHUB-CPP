// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
// Implementation of ScTransport. See ScTransport.h for the contract.
#include "ScTransport.h"

#include "CASExampleLog.h"

#include <libwebsockets.h>
#include <openssl/ssl.h>  // SSL_OP_NO_TLSv1* - TLS 1.3-only restriction

#include <cstdio>
#include <cstring>
#include <fstream>

namespace CASSc {

namespace {

// BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH from
// submodules/cas-bacnet-stack/source/BACnetStackConstants.h - a frame the
// stack could never accept anyway must never be queued for it (plan fact 8).
// As of the stack pin bump that closed cas-bacnet-stack#2225 (commit 2021e29f,
// "SC ingress buffer/ceilings now accept a maximum-size Annex AB frame"), this
// constant is gated on STACK_OPTION_DATA_LINK_LAYER_SC (compiled in for this
// example) and is now 1600 bytes - reaching ANSI/ASHRAE 135 Annex AB's
// 1600-octet minimum BVLC-SC relay size exactly (it was previously pinned at
// 1497, 103 bytes short of that minimum). Not #include-d directly:
// BACnetStackConstants.h is an internal stack header, not part of the public
// adapter surface this example otherwise depends on; the value is stable and
// cross-checked against source on every phase of this plan - see
// docs/bacnet-sc-transport-plan.md.
const std::size_t kMaxIngressBytes = 1600;

// A connection is dropped for sending a non-final-fragment frame that alone
// already exceeds this many header-parse attempts of nonsense... (not used -
// placeholder removed). See ScTransport::HandleServerCallback for the actual
// overflow handling.

bool FileReadable(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    std::ifstream f(path, std::ios::binary);
    return f.good();
}

// Parses "wss://host:port/path...". Only wss:// is accepted (BACnet/SC
// requires it - AddBACnetSCAcceptUri's own doc comment). host may be empty
// (e.g. "wss://:47819/") or "0.0.0.0", both of which mean "bind all
// interfaces" - both map to a NULL lws iface (listener use only).
// outPath is optional (nullptr for the listener, which does not route by
// path); when non-null it is set to the path component, defaulting to "/"
// when the URI has none - Connect() (below) needs it for
// lws_client_connect_info::path.
bool ParseWssUri(const std::string& uri, std::string* outHost, uint16_t* outPort,
                 std::string* outPath = nullptr) {
    static const char kScheme[] = "wss://";
    const std::size_t schemeLen = sizeof(kScheme) - 1;
    if (uri.compare(0, schemeLen, kScheme) != 0) {
        return false;
    }
    std::size_t hostStart = schemeLen;
    std::size_t pathSlash = uri.find('/', hostStart);
    std::string authority = (pathSlash == std::string::npos)
        ? uri.substr(hostStart)
        : uri.substr(hostStart, pathSlash - hostStart);
    if (outPath != nullptr) {
        *outPath = (pathSlash == std::string::npos) ? "/" : uri.substr(pathSlash);
    }
    if (authority.empty()) {
        return false;
    }
    const std::size_t colon = authority.rfind(':');
    if (colon == std::string::npos || colon + 1 >= authority.size()) {
        return false;  // a port is required - this example never guesses one
    }
    const std::string host = authority.substr(0, colon);
    const std::string portStr = authority.substr(colon + 1);
    char* end = nullptr;
    const long port = strtol(portStr.c_str(), &end, 10);
    if (end == portStr.c_str() || *end != '\0' || port <= 0 || port > 65535) {
        return false;
    }
    *outHost = host;
    *outPort = static_cast<uint16_t>(port);
    return true;
}

// True if `headerValue` (a comma-separated Sec-WebSocket-Protocol request
// list, possibly with spaces) contains `wanted` as one whole token. Used
// because lws's own negotiation can otherwise silently accept a connection on
// protocols[0] even when the client asked for something else entirely - a
// known footgun this example does not want (V1's "wrong subprotocol is
// rejected" case depends on this check, not on lws's default behaviour).
bool SubprotocolListContains(const char* headerValue, const std::string& wanted) {
    if (headerValue == nullptr) {
        return false;
    }
    std::string list(headerValue);
    std::size_t pos = 0;
    while (pos <= list.size()) {
        std::size_t comma = list.find(',', pos);
        std::string token = (comma == std::string::npos) ? list.substr(pos) : list.substr(pos, comma - pos);
        // Trim surrounding whitespace.
        std::size_t start = token.find_first_not_of(" \t");
        std::size_t stop = token.find_last_not_of(" \t");
        if (start != std::string::npos) {
            token = token.substr(start, stop - start + 1);
            if (token == wanted) {
                return true;
            }
        }
        if (comma == std::string::npos) {
            break;
        }
        pos = comma + 1;
    }
    return false;
}

// The single, process-wide instance currently bound to the listener context.
// lws hands callbacks to a plain C function pointer with no way to pass a
// C++ `this` other than through lws_context_user()/info.user, which we do
// set per-context - this pointer exists only so the trampoline function below
// has something to call `HandleServerCallback` through without becoming a
// member function itself (lws_protocols::callback must be a free function).
int LwsServerCallbackTrampoline(lws* wsi, lws_callback_reasons reason, void* user, void* in, std::size_t len) {
    lws_context* ctx = wsi != nullptr ? lws_get_context(wsi) : nullptr;
    if (ctx == nullptr) {
        return 0;  // called before/without a context (e.g. protocol init on a template wsi) - nothing to do
    }
    ScTransport* self = static_cast<ScTransport*>(lws_context_user(ctx));
    if (self == nullptr) {
        return 0;
    }
    return self->HandleServerCallback(wsi, static_cast<int>(reason), user, in, len);
}

// Connector-half sibling of the above - every ClientConnection's lws_context
// also sets info.user = this (Connect(), below), so the same "context user
// pointer, not a static singleton" pattern applies here too.
int LwsClientCallbackTrampoline(lws* wsi, lws_callback_reasons reason, void* user, void* in, std::size_t len) {
    lws_context* ctx = wsi != nullptr ? lws_get_context(wsi) : nullptr;
    if (ctx == nullptr) {
        return 0;
    }
    ScTransport* self = static_cast<ScTransport*>(lws_context_user(ctx));
    if (self == nullptr) {
        return 0;
    }
    return self->HandleClientCallback(wsi, static_cast<int>(reason), user, in, len);
}

}  // namespace

ScTransport::ScTransport() {}

ScTransport::~ScTransport() {
    DestroyListenerContext();
    // Outside of any lws callback (this is the destructor) - safe to destroy
    // every client context directly, unlike HandleClientCallback (see
    // DestroyClientContext's comment).
    for (auto& kv : m_clients) {
        DestroyClientContext(kv.second);
    }
    m_clients.clear();
    delete[] m_clientProtocols;
    m_clientProtocols = nullptr;
}

void ScTransport::Configure(const ScTlsFiles& tls, const std::string& acceptSubprotocol) {
    m_tls = tls;
    m_acceptSubprotocol = acceptSubprotocol;
    // Set once, here, so both m_protocols[0].name (listener, built in
    // StartListening()) and m_clientProtocols[0].name (connector, built in
    // EnsureClientProtocolsTable()) point at the SAME backing storage - see
    // the header's comment on m_protocolNameStorage.
    m_protocolNameStorage = acceptSubprotocol;
    m_configured = true;
}

void ScTransport::SetMaxConnectionAttemptsPerSecond(const uint32_t perSecond) {
    m_maxConnAttemptsPerSecond = perSecond;
    // Start the bucket full (burst up to the configured rate is allowed
    // immediately, e.g. right after startup) - see the header comment.
    m_rateLimitTokens = static_cast<double>(perSecond);
    m_rateLimitLastRefill = std::chrono::steady_clock::now();
}

bool ScTransport::AllowNewConnectionAttempt() {
    if (m_maxConnAttemptsPerSecond == 0) {
        return true;  // rate-limiting disabled
    }
    const auto now = std::chrono::steady_clock::now();
    const double elapsedSeconds = std::chrono::duration<double>(now - m_rateLimitLastRefill).count();
    m_rateLimitLastRefill = now;
    const double capacity = static_cast<double>(m_maxConnAttemptsPerSecond);
    const double refilled = m_rateLimitTokens + elapsedSeconds * capacity;
    // NOT std::min() here: this translation unit includes <windows.h>
    // (transitively, via libwebsockets.h) without NOMINMAX, which #defines
    // min/max as function-like macros that shadow std::min/std::max - a
    // well-known Windows.h footgun. A plain comparison sidesteps it entirely.
    m_rateLimitTokens = (refilled < capacity) ? refilled : capacity;
    if (m_rateLimitTokens >= 1.0) {
        m_rateLimitTokens -= 1.0;
        return true;
    }
    return false;
}

void ScTransport::LogListenFailureOnce(const std::string& reason) {
    if (m_loggedListenFailure) {
        return;
    }
    m_loggedListenFailure = true;
    fprintf(stderr, "BACnet/SC: %s\n", reason.c_str());
}

bool ScTransport::StartListening(const std::string& uri) {
    if (!m_configured) {
        LogListenFailureOnce("StartListening called before Configure()");
        return false;
    }
    if (m_listenerContext != nullptr) {
        if (m_listenUri == uri) {
            return true;  // already listening on exactly this URI
        }
        StopListening(m_listenUri);  // the accept URI changed - tear down and rebind
    }

    std::string host;
    uint16_t port = 0;
    if (!ParseWssUri(uri, &host, &port)) {
        LogListenFailureOnce("cannot start listening: \"" + uri + "\" is not a valid wss://host:port/... URI");
        return false;
    }

    if (!FileReadable(m_tls.certPath) || !FileReadable(m_tls.keyPath) || !FileReadable(m_tls.caCertPath)) {
        LogListenFailureOnce(
            "cannot start listening on " + uri + ": certificate files are missing/unreadable "
            "(cert=\"" + m_tls.certPath + "\" key=\"" + m_tls.keyPath + "\" ca=\"" + m_tls.caCertPath + "\"). "
            "Run: cmake -P scripts/generate-test-certs.cmake");
        return false;
    }

    // The protocol name string must outlive the context, so it lives on this
    // object (m_protocolNameStorage), not as a temporary. m_protocols itself
    // is heap-allocated (not a fixed array) so ScTransport.h does not need the
    // full `struct lws_protocols` definition - see the header's comment.
    m_protocolNameStorage = m_acceptSubprotocol;
    delete[] m_protocols;
    m_protocols = new lws_protocols[2];
    std::memset(m_protocols, 0, sizeof(lws_protocols) * 2);
    m_protocols[0].name = m_protocolNameStorage.c_str();
    m_protocols[0].callback = &LwsServerCallbackTrampoline;
    m_protocols[0].per_session_data_size = 0;  // per-connection state lives in m_peers, keyed by wsi*
    m_protocols[0].rx_buffer_size = 4096;
    // m_protocols[1] stays all-zero - the required NULL-callback terminator.

    lws_context_creation_info info;
    std::memset(&info, 0, sizeof(info));
    info.port = port;
    info.iface = (host.empty() || host == "0.0.0.0") ? nullptr : host.c_str();
    info.protocols = m_protocols;
    info.ssl_cert_filepath = m_tls.certPath.c_str();
    info.ssl_private_key_filepath = m_tls.keyPath.c_str();
    info.ssl_ca_filepath = m_tls.caCertPath.c_str();
    // Mutual TLS (SC nodes/hubs authenticate each other by certificate, AB.5.3)
    // + TLS 1.3 only (135-2024 AB.5.2 mandates 1.3; SSL_OP_NO_TLSv1/1_1/1_2/SSLv3
    // disables every older negotiable version, leaving only 1.3).
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
    info.ssl_options_set = SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_SSLv3;
    info.user = this;
    info.gid = static_cast<gid_t>(-1);
    info.uid = static_cast<uid_t>(-1);

    lws_context* ctx = lws_create_context(&info);
    if (ctx == nullptr) {
        LogListenFailureOnce("lws_create_context failed for " + uri + " (port " + std::to_string(port) +
                              " already in use? cert files malformed?)");
        return false;
    }

    m_listenerContext = ctx;
    m_listenUri = uri;
    m_nextClientId = 1;
    m_loggedListenFailure = false;
    printf("BACnet/SC: listening for WebSocket/TLS connections on %s (subprotocol \"%s\", TLS 1.3, mutual auth)\n",
           uri.c_str(), m_acceptSubprotocol.c_str());
    return true;
}

void ScTransport::DestroyListenerContext() {
    if (m_listenerContext == nullptr) {
        return;
    }
    // lws_context_destroy synchronously closes every live wsi, which re-enters
    // HandleServerCallback with LWS_CALLBACK_CLOSED for each accepted peer
    // still in m_peers (queuing a Disconnected status event per peer - see the
    // CLOSED case below). That is harmless here: StopListening() is only ever
    // called because the STACK already decided to stop the hub function (it
    // has already forgotten these peers itself - see
    // BACnetDataLinkSC::SuspendCommunication in the stack source), so a later
    // DrainStatusEvents() call reporting Disconnected for an already-forgotten
    // peer is the documented "not logged as an error" no-op case (plan,
    // ScTransportRouter subsection).
    lws_context_destroy(m_listenerContext);
    m_listenerContext = nullptr;
    m_listenUri.clear();
    m_peers.clear();
    m_connStringToWsi.clear();
    delete[] m_protocols;
    m_protocols = nullptr;
}

void ScTransport::StopListening(const std::string& uri) {
    if (m_listenerContext == nullptr || m_listenUri != uri) {
        return;  // not listening on this URI - nothing to do
    }
    printf("BACnet/SC: no longer listening on %s\n", uri.c_str());
    DestroyListenerContext();
}

bool ScTransport::IsListening() const {
    return m_listenerContext != nullptr;
}

void ScTransport::EnsureClientProtocolsTable() {
    if (m_clientProtocols != nullptr) {
        return;
    }
    // Shared by every ClientConnection's context - see the header comment.
    // Uses m_protocolNameStorage, the SAME backing string Configure() set for
    // the listener's table, so both halves always offer the identical
    // subprotocol name.
    m_clientProtocols = new lws_protocols[2];
    std::memset(m_clientProtocols, 0, sizeof(lws_protocols) * 2);
    m_clientProtocols[0].name = m_protocolNameStorage.c_str();
    m_clientProtocols[0].callback = &LwsClientCallbackTrampoline;
    m_clientProtocols[0].per_session_data_size = 0;  // per-connection state lives in ClientConnection, reached via lws_get_opaque_user_data
    m_clientProtocols[0].rx_buffer_size = 4096;
    // m_clientProtocols[1] stays all-zero - the required NULL-callback terminator.
}

void ScTransport::DestroyClientContext(ClientConnection& conn) {
    if (conn.context != nullptr) {
        // Synchronously closes the wsi if still open, re-entering
        // HandleClientCallback with LWS_CALLBACK_CLIENT_CLOSED - harmless
        // here for the same reason DestroyListenerContext's identical note
        // gives (a status event for a connection this method's OWN caller is
        // already tearing down is not useful, but queuing it costs nothing).
        lws_context_destroy(conn.context);
        conn.context = nullptr;
    }
    conn.wsi = nullptr;
}

bool ScTransport::Connect(const std::string& uri) {
    if (!m_configured) {
        fprintf(stderr, "BACnet/SC: Connect(\"%s\") requested before Configure()\n", uri.c_str());
        return false;
    }
    if (!FileReadable(m_tls.certPath) || !FileReadable(m_tls.keyPath) || !FileReadable(m_tls.caCertPath)) {
        fprintf(stderr,
                "BACnet/SC: cannot Connect(\"%s\"): certificate files are missing/unreadable "
                "(cert=\"%s\" key=\"%s\" ca=\"%s\"). Run: cmake -P scripts/generate-test-certs.cmake\n",
                uri.c_str(), m_tls.certPath.c_str(), m_tls.keyPath.c_str(), m_tls.caCertPath.c_str());
        return false;
    }

    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!ParseWssUri(uri, &host, &port, &path) || host.empty()) {
        // Unlike the listener, an empty/omitted host is NOT valid here - a
        // connector must dial a specific hub, never "0.0.0.0" (that is a bind
        // address, meaningless as a dial target).
        fprintf(stderr, "BACnet/SC: cannot Connect(): \"%s\" is not a valid wss://host:port/path URI\n",
                uri.c_str());
        return false;
    }

    // A fresh dial every time Connect() is called for this URI - tear down
    // any stale context first (a previous attempt that already closed/errored;
    // per plan fact 7 this class itself never re-dials, so reaching this line
    // again for the same URI only ever happens because the CALLER - ultimately
    // the stack's own retry/reconnect timer - asked for it again).
    auto existing = m_clients.find(uri);
    if (existing != m_clients.end()) {
        DestroyClientContext(existing->second);
        m_clients.erase(existing);
    }

    EnsureClientProtocolsTable();

    // std::map<std::string, ClientConnection>::operator[] gives a reference
    // that stays valid across later inserts/erases of OTHER keys (see the
    // header's comment on m_clients) - safe to hand its address to lws as
    // opaque_user_data below and keep using it after this call returns.
    ClientConnection& conn = m_clients[uri];
    conn.uri = uri;

    lws_context_creation_info info;
    std::memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;  // connector role only - this context is never a server
    info.protocols = m_clientProtocols;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.client_ssl_ca_filepath = m_tls.caCertPath.c_str();          // validates the HUB's certificate
    info.client_ssl_cert_filepath = m_tls.certPath.c_str();          // this device's own operational cert (mutual TLS)
    info.client_ssl_private_key_filepath = m_tls.keyPath.c_str();
    // TLS 1.3 only, same restriction as the listener half (135-2024 AB.5.2).
    info.ssl_client_options_set = SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_SSLv3;
    info.user = this;
    info.gid = static_cast<gid_t>(-1);
    info.uid = static_cast<uid_t>(-1);

    lws_context* ctx = lws_create_context(&info);
    if (ctx == nullptr) {
        fprintf(stderr, "BACnet/SC: Connect(\"%s\"): lws_create_context failed\n", uri.c_str());
        m_clients.erase(uri);
        return false;
    }
    conn.context = ctx;

    lws_client_connect_info ccinfo;
    std::memset(&ccinfo, 0, sizeof(ccinfo));
    ccinfo.context = ctx;
    ccinfo.address = host.c_str();
    ccinfo.port = port;
    ccinfo.path = path.c_str();
    ccinfo.host = host.c_str();
    ccinfo.origin = host.c_str();
    ccinfo.protocol = m_acceptSubprotocol.c_str();  // "hub.bsc.bacnet.org" - plan fact 1, NOT plugfest-example's wrong "hub.bacnet.org"
    // LCCSCF_USE_SSL: TLS on. LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK: the CA
    // chain is STILL fully verified (client_ssl_ca_filepath above requires a
    // valid chain to m_tls.caCertPath) - only the hostname-in-certificate
    // check is skipped. BACnet/SC certificates identify a DEVICE (by its
    // UUID/VMAC-derived identity, 135-2024 AB.1.5.3), not a DNS hostname the
    // way an ordinary HTTPS server certificate does, so requiring the SAN to
    // list "127.0.0.1"/the hub's hostname would reject a conformant BACnet/SC
    // hub whose certificate (correctly) does not encode that - see the plan's
    // Connector subsection and open risk #6 (this app's cert policy is
    // CA-chain-only; there is no hostname or UUID-in-SAN binding here).
    ccinfo.ssl_connection = LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    ccinfo.opaque_user_data = &conn;
    lws* wsi = nullptr;
    ccinfo.pwsi = &wsi;

    if (lws_client_connect_via_info(&ccinfo) == nullptr) {
        // A hard, immediate failure (bad address, etc.) - note lws may ALSO
        // have already called HandleClientCallback synchronously with
        // LWS_CALLBACK_CLIENT_CONNECTION_ERROR for this same attempt (plan
        // fact 6); that queues its own Error(4) status event, which is fine -
        // an extra queued event for a connection we are about to erase here
        // is harmless (DrainStatusEvents' "not accepted" case, main.cpp).
        fprintf(stderr, "BACnet/SC: Connect(\"%s\"): lws_client_connect_via_info failed immediately\n",
                uri.c_str());
        lws_context_destroy(ctx);
        m_clients.erase(uri);
        return false;
    }
    conn.wsi = wsi;
    printf("BACnet/SC: dialing out to %s (subprotocol \"%s\", TLS 1.3, mutual auth)\n",
           uri.c_str(), m_acceptSubprotocol.c_str());
    return true;
}

void ScTransport::Disconnect(const std::string& connStr) {
    // Case 1: an accepted server peer ("<acceptUri>|client=N", Phase 2 half).
    auto serverIt = m_connStringToWsi.find(connStr);
    if (serverIt != m_connStringToWsi.end()) {
        lws_close_reason(serverIt->second, LWS_CLOSE_STATUS_NORMAL, nullptr, 0);
        lws_callback_on_writable(serverIt->second);  // completes the close handshake asynchronously
        return;
    }
    // Case 2: an outbound connector URI (this phase).
    auto clientIt = m_clients.find(connStr);
    if (clientIt != m_clients.end() && clientIt->second.wsi != nullptr) {
        lws_close_reason(clientIt->second.wsi, LWS_CLOSE_STATUS_NORMAL, nullptr, 0);
        lws_callback_on_writable(clientIt->second.wsi);
        return;
    }
    // Unknown/already-closed connString - no-op, matching the header's contract.
}

ScTransport::PeerConnection* ScTransport::FindPeerByWsi(lws* wsi) {
    auto it = m_peers.find(wsi);
    return (it == m_peers.end()) ? nullptr : &it->second;
}

bool ScTransport::Send(const std::string& connStr, const uint8_t* data, uint16_t len) {
    // Case 1: an accepted server peer ("<acceptUri>|client=N", Phase 2 half).
    auto serverIt = m_connStringToWsi.find(connStr);
    if (serverIt != m_connStringToWsi.end()) {
        PeerConnection* peer = FindPeerByWsi(serverIt->second);
        if (peer == nullptr) {
            return false;
        }
        std::vector<uint8_t> framed(static_cast<std::size_t>(LWS_PRE) + len);
        if (len > 0) {
            std::memcpy(framed.data() + LWS_PRE, data, len);
        }
        peer->txQueue.push_back(std::move(framed));
        lws_callback_on_writable(peer->wsi);
        return true;
    }

    // Case 2: an outbound connector connection, keyed by the URI Connect()
    // was called with. A connString that names a connector entry whose
    // wsi is currently null (never established, or already closed) is
    // treated as unknown - matching the header's "unknown/closed" contract.
    auto clientIt = m_clients.find(connStr);
    if (clientIt != m_clients.end() && clientIt->second.wsi != nullptr) {
        std::vector<uint8_t> framed(static_cast<std::size_t>(LWS_PRE) + len);
        if (len > 0) {
            std::memcpy(framed.data() + LWS_PRE, data, len);
        }
        clientIt->second.txQueue.push_back(std::move(framed));
        lws_callback_on_writable(clientIt->second.wsi);
        return true;
    }

    return false;  // unknown/closed peer - caller (the router) returns 0 to the stack
}

void ScTransport::Service() {
    // Phase 1 spike mechanism (a) - see docs/bacnet-sc-transport-plan.md and
    // the class header comment. Confirmed non-blocking on Windows.
    if (m_listenerContext != nullptr) {
        lws_cancel_service(m_listenerContext);
        lws_service(m_listenerContext, 0);
    }
    // One client lws_context per connector connection (plan's Connector
    // subsection) - pump every live one the same non-blocking way.
    for (auto& kv : m_clients) {
        if (kv.second.context != nullptr) {
            lws_cancel_service(kv.second.context);
            lws_service(kv.second.context, 0);
        }
    }
}

bool ScTransport::PopReceived(ScReceivedFrame* outFrame) {
    if (m_rxQueue.empty() || outFrame == nullptr) {
        return false;
    }
    *outFrame = std::move(m_rxQueue.front());
    m_rxQueue.pop_front();
    return true;
}

bool ScTransport::PopStatusEvent(ScStatusEvent* outEvent) {
    if (m_statusQueue.empty() || outEvent == nullptr) {
        return false;
    }
    *outEvent = m_statusQueue.front();
    m_statusQueue.pop_front();
    return true;
}

int ScTransport::HandleServerCallback(lws* wsi, int reasonInt, void* user, void* in, std::size_t len) {
    (void)user;
    const lws_callback_reasons reason = static_cast<lws_callback_reasons>(reasonInt);

    switch (reason) {
        case LWS_CALLBACK_FILTER_NETWORK_CONNECTION: {
            // Fires at raw-socket accept() time, BEFORE TLS negotiation and
            // before any BACnet/SC-specific state exists for this connection
            // (lws's own doc comment: "wsi still pointing to the main server
            // socket" - there is no PeerConnection/connection string yet, and
            // won't be one if this rejects). This is the earliest, cheapest
            // point this transport can gate a flood of connection attempts -
            // see ScTransport::SetMaxConnectionAttemptsPerSecond's header
            // comment for why this is a separate control from
            // sc-max-hub-connections. Returning non-zero here makes lws hang
            // up immediately, before sending or receiving anything - no TLS
            // handshake CPU/memory is spent on a rejected attempt.
            if (!AllowNewConnectionAttempt()) {
                CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                    "SC rate limit: rejecting new connection attempt on %s - more than %u attempt(s)/sec "
                    "(rejected before TLS handshake; see --sc-rate-limit)",
                    m_listenUri.c_str(), (unsigned)m_maxConnAttemptsPerSecond);
                return -1;
            }
            break;
        }

        case LWS_CALLBACK_ESTABLISHED: {
            // Verify the client actually asked for our subprotocol ourselves -
            // see SubprotocolListContains's comment for why this is not left to
            // lws's own negotiation.
            char requested[256] = {0};
            lws_hdr_copy(wsi, requested, static_cast<int>(sizeof(requested)), WSI_TOKEN_PROTOCOL);
            if (!SubprotocolListContains(requested, m_acceptSubprotocol)) {
                fprintf(stderr, "BACnet/SC: rejecting connection - client asked for subprotocol(s) "
                                "\"%s\", not \"%s\"\n", requested, m_acceptSubprotocol.c_str());
                lws_close_reason(wsi, LWS_CLOSE_STATUS_PROTOCOL_ERR,
                                 (unsigned char*)"unsupported subprotocol", 24);
                return -1;
            }

            // Mint the accepted-peer connection string (plan fact 2, verified
            // against BACnetDataLinkSC::DoesConfiguredUriMatch): "<acceptUri>|client=<N>".
            const std::string connStr = m_listenUri + "|client=" + std::to_string(m_nextClientId++);
            PeerConnection& peer = m_peers[wsi];
            peer.wsi = wsi;
            peer.connectionString = connStr;
            m_connStringToWsi[connStr] = wsi;
            printf("BACnet/SC: accepted WebSocket connection - peer=\"%s\"\n", connStr.c_str());
            // Audit trail (Task 1): the accepted-peer connection string
            // ("<acceptUri>|client=N") is the identity this transport layer
            // actually has at this point - it is the SAME identifier the
            // stack will use as this peer's BACnet/SC source address for the
            // rest of the connection's life (plan fact 2). A BACnet/SC VMAC/
            // UUID is NOT available here: that identity is only established
            // once the stack completes its own Connect-Request/Accept
            // exchange over this socket (ordinary RX data, handled below,
            // processed by the stack - not visible to this transport) - see
            // ScStatusEvent's header comment and TODO.md for this documented
            // boundary. CASExampleHelper::Log already prefixes every line
            // with a UTC timestamp (common/CASExampleLog.cpp), which is the
            // "<UTC timestamp>" this audit line needs - not duplicated here.
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                "SC audit: peer \"%s\" connected", connStr.c_str());
            // Deliberately NOT queuing a Connected(2) status event here - see
            // ScStatusEvent's doc comment and plan open risk #7: an accepted
            // socket is not yet a BACnet/SC "connection" until the stack's own
            // Connect-Request/Accept exchange (which arrives as ordinary RX
            // data, handled below) completes.
            break;
        }

        case LWS_CALLBACK_RECEIVE: {
            PeerConnection* peer = FindPeerByWsi(wsi);
            if (peer == nullptr) {
                break;
            }
            if (HandleIncomingFragment(wsi, in, len, peer->connectionString, m_listenUri,
                                       &peer->rxAssembly, &peer->rxOverflow)) {
                return -1;
            }
            break;
        }

        case LWS_CALLBACK_SERVER_WRITEABLE: {
            PeerConnection* peer = FindPeerByWsi(wsi);
            if (peer == nullptr || peer->txQueue.empty()) {
                break;
            }
            std::vector<uint8_t>& framed = peer->txQueue.front();
            const std::size_t payloadLen = framed.size() - static_cast<std::size_t>(LWS_PRE);
            const int written = lws_write(wsi, framed.data() + LWS_PRE,
                                          payloadLen, LWS_WRITE_BINARY);
            peer->txQueue.pop_front();
            if (written < 0 || static_cast<std::size_t>(written) < payloadLen) {
                fprintf(stderr, "BACnet/SC: short/failed write to \"%s\" (%d of %zu bytes) - closing\n",
                        peer->connectionString.c_str(), written, payloadLen);
                return -1;
            }
            if (!peer->txQueue.empty()) {
                lws_callback_on_writable(wsi);  // more frames queued - ask for another turn
            }
            break;
        }

        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE: {
            PeerConnection* peer = FindPeerByWsi(wsi);
            if (peer != nullptr && in != nullptr && len >= 2) {
                const uint8_t* bytes = static_cast<const uint8_t*>(in);
                peer->lastCloseCode = static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
            }
            break;
        }

        case LWS_CALLBACK_CLOSED: {
            PeerConnection* peer = FindPeerByWsi(wsi);
            if (peer != nullptr) {
                // Plan fact 3 / open risk #7: a clean close (1000, or no close
                // frame at all - an abrupt drop) reports Disconnected(3);
                // anything else reports Error(4).
                const uint8_t status = (peer->lastCloseCode == 0 || peer->lastCloseCode == 1000)
                    ? 3 /* WebsocketStatus_Disconnected */
                    : 4 /* WebsocketStatus_Error */;
                ScStatusEvent evt;
                evt.uri = peer->connectionString;
                evt.status = status;
                evt.closeCode = peer->lastCloseCode;
                m_statusQueue.push_back(evt);
                printf("BACnet/SC: peer \"%s\" disconnected (status=%u closeCode=%u)\n",
                       peer->connectionString.c_str(), (unsigned)status, (unsigned)peer->lastCloseCode);
                // Audit trail (Task 1) - same identity/timestamp rationale as
                // the "connected" line above.
                CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                    "SC audit: peer \"%s\" disconnected (closeCode=%u)",
                    peer->connectionString.c_str(), (unsigned)peer->lastCloseCode);
                m_connStringToWsi.erase(peer->connectionString);
                m_peers.erase(wsi);
            }
            break;
        }

        default:
            break;
    }
    return 0;
}

bool ScTransport::HandleIncomingFragment(lws* wsi, const void* in, std::size_t len,
                                         const std::string& sourceConnStr, const std::string& destConnStr,
                                         std::vector<uint8_t>* rxAssembly, bool* rxOverflow) {
    if (!lws_frame_is_binary(wsi)) {
        // BACnet/SC is binary-framed only (135-2024 AB.7.4). Reject a text
        // frame with 1003 (plan/V1 negative case) - shared by both roles.
        fprintf(stderr, "BACnet/SC: peer \"%s\" sent a non-binary frame - closing (1003)\n",
                sourceConnStr.c_str());
        lws_close_reason(wsi, LWS_CLOSE_STATUS_UNACCEPTABLE_OPCODE, (unsigned char*)"binary only", 11);
        return true;
    }

    const uint8_t* bytes = static_cast<const uint8_t*>(in);
    if (!*rxOverflow) {
        if (rxAssembly->size() + len > kMaxIngressBytes) {
            // Plan fact 8: BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH is 1600
            // bytes (post cas-bacnet-stack#2225 fix) - a bigger frame is
            // discarded and logged, never handed to the stack.
            *rxOverflow = true;
            rxAssembly->clear();
            fprintf(stderr, "BACnet/SC: discarding oversized frame (> %zu bytes) from \"%s\" - "
                            "ingress ceiling (BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH)\n",
                    kMaxIngressBytes, sourceConnStr.c_str());
        } else if (len > 0) {
            rxAssembly->insert(rxAssembly->end(), bytes, bytes + len);
        }
    }

    if (lws_is_final_fragment(wsi)) {
        if (!*rxOverflow) {
            ScReceivedFrame frame;
            frame.sourceConnectionString = sourceConnStr;
            frame.destinationConnectionString = destConnStr;
            frame.data = *rxAssembly;
            m_rxQueue.push_back(std::move(frame));
        }
        rxAssembly->clear();
        *rxOverflow = false;
    }
    return false;
}

int ScTransport::HandleClientCallback(lws* wsi, int reasonInt, void* user, void* in, std::size_t len) {
    (void)user;
    const lws_callback_reasons reason = static_cast<lws_callback_reasons>(reasonInt);
    // Every reason below fires on a wsi lws created from THIS connection's own
    // Connect() call, which set ccinfo.opaque_user_data = &conn (a stable
    // reference into m_clients - see the header's comment on that map) - so
    // this lookup is valid for every case, including one that fires
    // synchronously from inside Connect() itself (plan fact 6).
    ClientConnection* conn = static_cast<ClientConnection*>(lws_get_opaque_user_data(wsi));

    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            if (conn == nullptr) {
                break;
            }
            conn->wsi = wsi;
            printf("BACnet/SC: connected to hub \"%s\"\n", conn->uri.c_str());
            ScStatusEvent evt;
            evt.uri = conn->uri;
            evt.status = 2;  // WebsocketStatus_Connected (plan fact 3)
            evt.closeCode = 0;
            m_statusQueue.push_back(evt);
            if (!conn->txQueue.empty()) {
                lws_callback_on_writable(wsi);  // a Send() may have queued before ESTABLISHED fired
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            if (conn == nullptr) {
                break;
            }
            const std::string detail = (in != nullptr) ? std::string(static_cast<const char*>(in), len) : std::string();
            fprintf(stderr, "BACnet/SC: Connect(\"%s\") failed: %s\n", conn->uri.c_str(), detail.c_str());
            ScStatusEvent evt;
            evt.uri = conn->uri;
            evt.status = 4;  // WebsocketStatus_Error (plan fact 3)
            evt.closeCode = 0;
            m_statusQueue.push_back(evt);
            conn->wsi = nullptr;
            break;
        }

        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE: {
            // Same generic (non-CLIENT_-prefixed) reason the listener half
            // uses - fires for a client-role wsi too. Recorded only for the
            // log line below; unlike the listener half, this class does not
            // branch Disconnected-vs-Error on it for the connector (see
            // ScStatusEvent's header comment).
            if (conn != nullptr && in != nullptr && len >= 2) {
                const uint8_t* bytes = static_cast<const uint8_t*>(in);
                conn->lastCloseCode = static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            if (conn == nullptr) {
                break;
            }
            // destConnStr is empty for a connector-side frame - see
            // ScReceivedFrame's header comment ("empty (connector)").
            if (HandleIncomingFragment(wsi, in, len, conn->uri, std::string(),
                                       &conn->rxAssembly, &conn->rxOverflow)) {
                return -1;
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            if (conn == nullptr || conn->txQueue.empty()) {
                break;
            }
            std::vector<uint8_t>& framed = conn->txQueue.front();
            const std::size_t payloadLen = framed.size() - static_cast<std::size_t>(LWS_PRE);
            const int written = lws_write(wsi, framed.data() + LWS_PRE, payloadLen, LWS_WRITE_BINARY);
            conn->txQueue.pop_front();
            if (written < 0 || static_cast<std::size_t>(written) < payloadLen) {
                fprintf(stderr, "BACnet/SC: short/failed write to hub \"%s\" (%d of %zu bytes) - closing\n",
                        conn->uri.c_str(), written, payloadLen);
                return -1;
            }
            if (!conn->txQueue.empty()) {
                lws_callback_on_writable(wsi);  // more frames queued - ask for another turn
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_CLOSED: {
            if (conn == nullptr) {
                break;
            }
            // Plan spec for the connector half: EVERY close (clean or not)
            // reports Disconnected(3) here - LWS_CALLBACK_CLIENT_CONNECTION_ERROR
            // above is the only path that reports Error(4) for this half (unlike
            // the listener half's closeCode-based split - see ScStatusEvent's
            // header comment).
            ScStatusEvent evt;
            evt.uri = conn->uri;
            evt.status = 3;  // WebsocketStatus_Disconnected (plan fact 3)
            evt.closeCode = conn->lastCloseCode;
            m_statusQueue.push_back(evt);
            printf("BACnet/SC: hub connection \"%s\" closed (closeCode=%u)\n",
                   conn->uri.c_str(), (unsigned)conn->lastCloseCode);
            conn->wsi = nullptr;
            break;
        }

        default:
            break;
    }
    return 0;
}

}  // namespace CASSc
