// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
// Implementation of ScTransport. See ScTransport.h for the contract.
#include "ScTransport.h"

#include <libwebsockets.h>
#include <openssl/ssl.h>  // SSL_OP_NO_TLSv1* - TLS 1.3-only restriction

#include <cstdio>
#include <cstring>
#include <fstream>

namespace CASSc {

namespace {

// BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH from
// submodules/cas-bacnet-stack/source/BACnetStackConstants.h:330 - a frame the
// stack could never accept anyway must never be queued for it (plan fact 8).
// Not #include-d directly: BACnetStackConstants.h is an internal stack header,
// not part of the public adapter surface this example otherwise depends on;
// the value is stable (Annex AB's own BVLC size floor) and cross-checked
// against source on every phase of this plan - see docs/bacnet-sc-transport-plan.md.
const std::size_t kMaxIngressBytes = 1497;

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
// interfaces" - both map to a NULL lws iface.
bool ParseWssUri(const std::string& uri, std::string* outHost, uint16_t* outPort) {
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

}  // namespace

ScTransport::ScTransport() {}

ScTransport::~ScTransport() {
    DestroyListenerContext();
}

void ScTransport::Configure(const ScTlsFiles& tls, const std::string& acceptSubprotocol) {
    m_tls = tls;
    m_acceptSubprotocol = acceptSubprotocol;
    m_configured = true;
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

bool ScTransport::Connect(const std::string& uri) {
    // PHASE 3 STUB - see the class header comment. Never claim a connection
    // attempt that was not actually made (main.cpp's CallbackInitiateWebsocket
    // relies on that honesty, same as the Phase-0/1 transport stub did).
    printf("BACnet/SC: Connect(\"%s\") requested - the connector half is not yet "
           "implemented (Phase 3 of docs/bacnet-sc-transport-plan.md).\n", uri.c_str());
    return false;
}

void ScTransport::Disconnect(const std::string& connStr) {
    (void)connStr;
    // No-op: the connector half (the only thing that could have an outbound
    // connection to disconnect) is not implemented yet - see Connect() above.
}

ScTransport::PeerConnection* ScTransport::FindPeerByWsi(lws* wsi) {
    auto it = m_peers.find(wsi);
    return (it == m_peers.end()) ? nullptr : &it->second;
}

bool ScTransport::Send(const std::string& connStr, const uint8_t* data, uint16_t len) {
    auto it = m_connStringToWsi.find(connStr);
    if (it == m_connStringToWsi.end()) {
        return false;  // unknown/closed peer - caller (the router) returns 0 to the stack
    }
    PeerConnection* peer = FindPeerByWsi(it->second);
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

void ScTransport::Service() {
    if (m_listenerContext != nullptr) {
        // Phase 1 spike mechanism (a) - see docs/bacnet-sc-transport-plan.md and
        // the class header comment. Confirmed non-blocking on Windows.
        lws_cancel_service(m_listenerContext);
        lws_service(m_listenerContext, 0);
    }
    // A connector context list would be pumped here too, once Phase 3 adds one.
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
            if (!lws_frame_is_binary(wsi)) {
                // BACnet/SC is binary-framed only (135-2024 AB.7.4). Reject a
                // text frame with 1003 (plan/V1 negative case).
                fprintf(stderr, "BACnet/SC: peer \"%s\" sent a non-binary frame - closing (1003)\n",
                        peer->connectionString.c_str());
                lws_close_reason(wsi, LWS_CLOSE_STATUS_UNACCEPTABLE_OPCODE,
                                 (unsigned char*)"binary only", 11);
                return -1;
            }

            const uint8_t* bytes = static_cast<const uint8_t*>(in);
            if (!peer->rxOverflow) {
                if (peer->rxAssembly.size() + len > kMaxIngressBytes) {
                    // Plan fact 8: BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH is
                    // 1497 bytes - a bigger frame is discarded and logged, never
                    // handed to the stack.
                    peer->rxOverflow = true;
                    peer->rxAssembly.clear();
                    fprintf(stderr, "BACnet/SC: discarding oversized frame (> %zu bytes) from \"%s\" - "
                                    "ingress ceiling (BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH)\n",
                            kMaxIngressBytes, peer->connectionString.c_str());
                } else if (len > 0) {
                    peer->rxAssembly.insert(peer->rxAssembly.end(), bytes, bytes + len);
                }
            }

            if (lws_is_final_fragment(wsi)) {
                if (!peer->rxOverflow) {
                    ScReceivedFrame frame;
                    frame.sourceConnectionString = peer->connectionString;
                    frame.destinationConnectionString = m_listenUri;
                    frame.data = peer->rxAssembly;
                    m_rxQueue.push_back(std::move(frame));
                }
                peer->rxAssembly.clear();
                peer->rxOverflow = false;
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

}  // namespace CASSc
