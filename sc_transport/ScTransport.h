// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
#pragma once

// ScTransport.h
// =============================================================================
// A thin libwebsockets(+OpenSSL) wrapper that supplies the raw WebSocket/TLS
// transport BACnet/SC needs. The CAS BACnet Stack owns the BACnet/SC PROTOCOL
// (Hello handshake, hub/node state machines, BVLC framing) - see main.cpp's
// file header - and asks the host for a transport through four callbacks. This
// class IS that transport, for the two roles BACnet/SC defines:
//
//   * Listener  (hub function "accept" role) - Phase 2 implements it fully.
//     StartListening()/StopListening() open/close a server lws_context that
//     accepts mutually-authenticated TLS 1.3 WebSocket connections offering the
//     "hub.bsc.bacnet.org" subprotocol (135-2024 AB.7.1 - NOT "hub.bacnet.org",
//     see docs/bacnet-sc-transport-plan.md fact 1).
//   * Connector (hub/node "initiate" role) - THIS PHASE (3) implements it
//     fully. Connect()/Disconnect() open/close ONE client lws_context PER
//     CONNECTION (CONTEXT_PORT_NO_LISTEN), keyed by the exact URI string the
//     stack passed to CallbackInitiateWebsocket. Same subprotocol, same TLS
//     1.3-only restriction, same mutual-TLS identity (this device's own
//     cert/key from Configure()) as the listener half - a BACnet/SC device
//     presents ONE identity regardless of which role a given socket plays.
//
// THREADING / RE-ENTRANCY (plan fact 6): every method here runs on the caller's
// thread (the main loop's thread, single-threaded in this example) and every
// libwebsockets callback also runs synchronously on that SAME thread, inside
// Service() OR (fact 6's other half) synchronously from INSIDE Connect() itself
// (lws can invoke CLIENT_CONNECTION_ERROR before lws_client_connect_via_info
// even returns, for an immediate failure). Neither HandleServerCallback nor
// HandleClientCallback below call BACnetStack_* - they only touch the queues
// (m_rxQueue, m_statusQueue) and lws itself. The stack is told about received
// frames and status changes only when the MAIN LOOP later drains those queues
// via PopReceived()/PopStatusEvent() - never synchronously from inside a
// callback. This is what makes the Connect()-calls-back-synchronously case
// safe: Connect() itself never touches BACnetStack_* either.
//
// NON-BLOCKING SERVICE (plan fact 9 / Phase 1 spike finding): Service() pumps
// each live lws_context - the listener's, plus one per live client/connector
// connection - with `lws_cancel_service(ctx); lws_service(ctx, 0);` - mechanism
// (a) from docs/bacnet-sc-transport-plan.md, confirmed non-blocking on Windows
// by the Phase 1 spike (sc_transport_spike.cpp, now removed).
//
// NO AUTO-RECONNECT (plan fact 7): the stack owns every timer - heartbeat,
// reconnect, failover. This class NEVER re-dials on its own after a
// CLIENT_CLOSED/CLIENT_CONNECTION_ERROR; it only dials when the stack calls
// Connect() again (which it does, on its own retry timer, via
// CallbackInitiateWebsocket in main.cpp). Connect() unconditionally tears down
// and replaces any previous lws_context for the same URI, so calling it again
// after a failure is exactly how the stack's retry is expected to work here.
//
// INGRESS CEILING (plan fact 8): BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH is
// 1600 bytes (post cas-bacnet-stack#2225 fix - previously 1497, 103 bytes
// short of Annex AB's 1600-octet minimum BVLC-SC relay size). A reassembled
// WebSocket message larger than that is discarded and logged here - it is
// never handed to PopReceived()/the stack.
// =============================================================================

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

// Forward declarations - avoid leaking <libwebsockets.h> (and therefore every
// OpenSSL header it pulls in) into every translation unit that includes this
// header. Only ScTransport.cpp needs the real definitions.
struct lws_context;
struct lws;
struct lws_protocols;

namespace CASSc {

// PEM file paths for one TLS identity: this device's own operational
// certificate + private key, plus the CA bundle used to validate the peer.
// The listener requires all three (mutual TLS - AB requires a conformant SC
// node to present a client certificate); see scripts/generate-test-certs.cmake
// for how a lab set of these is produced.
struct ScTlsFiles {
    std::string caCertPath;    // ca.crt - validates the PEER's certificate
    std::string certPath;      // this device's own operational certificate
    std::string keyPath;       // this device's own private key (never shared)
};

// One reassembled BACnet/SC BVLC message, plus who it came from/is addressed
// to, exactly as ScTransportRouter needs to hand to
// BACnetStack_RegisterCallbackReceiveMessageForPort's callback:
//   sourceConnectionString      - the accepted-peer string "<acceptUri>|client=N"
//                                 the stack should use as the SOURCE ADDRESS,
//                                 and later as the address to Send() a reply to
//                                 (plan fact 2; matches DoesConfiguredUriMatch
//                                 in source/BACnetDataLinkSC.cpp).
//   destinationConnectionString - the bare accept URI (listener) or empty
//                                 (connector - Phase 3).
struct ScReceivedFrame {
    std::string sourceConnectionString;
    std::string destinationConnectionString;
    std::vector<uint8_t> data;
};

// A connection-status change to report to the stack via
// BACnetStack_SetBACnetSCWebSocketStatus(uri, uriLength, status, closeCode).
// `status` uses BACnetSCConstants::BACnetSCWebsocketStatus exactly (plan fact
// 3, verified against source/BACnetSCConstants.h:93-99 - Connecting=1,
// Connected=2, Disconnected=3, Error=4).
//
// For an ACCEPTED (listener-side) peer this class only ever queues
// Disconnected/Error (never Connecting/Connected - an accepted socket does not
// become a "connection" the stack tracks until its own Connect-Request/Accept
// exchange finishes, which the stack, not this transport, is responsible for -
// see docs/bacnet-sc-transport-plan.md open risk #7).
//
// For an OUTBOUND (connector-side) connection this class queues Connected(2)
// on LWS_CALLBACK_CLIENT_ESTABLISHED (the WebSocket upgrade itself completing
// - the connector's own Connect-Request/Accept exchange over that socket is,
// again, the stack's problem, not this transport's), Error(4) on
// LWS_CALLBACK_CLIENT_CONNECTION_ERROR (TLS/handshake/upgrade failure), and
// Disconnected(3) on LWS_CALLBACK_CLIENT_CLOSED (any later close, clean or
// not - unlike the listener half, the connector does not distinguish an
// abnormal close as Error here; open risk #7 only covers the accepted-peer
// case).
struct ScStatusEvent {
    std::string uri;
    uint8_t status;      // BACnetSCConstants::BACnetSCWebsocketStatus (Connecting=1..Error=4)
    uint32_t closeCode;  // WebSocket close code if known, else 0
};

// Cumulative counters for the health/metrics keypress + HTTP endpoint (added
// this batch) - reuses the audit-trail (connect/disconnect) and rate-limiter
// bookkeeping this class already had (see LWS_CALLBACK_ESTABLISHED/CLOSED and
// AllowNewConnectionAttempt() in the .cpp) rather than inventing a parallel
// counting scheme. All counters are since-process-start; there is no
// persistence across restarts. currentPeerCount is the live count (listener
// half only - accepted BACnet/SC peers), directly comparable against
// main.cpp's g_scMaxHubConnections. rx/tx counters cover BOTH halves
// (listener peers and any outbound connector connection): a message is
// counted once it is a complete, reassembled BVLC frame (RX) or once lws has
// actually written it to the socket (TX) - never a partial fragment.
struct ScTransportMetrics {
    uint64_t totalConnects = 0;       // listener half: peers accepted (LWS_CALLBACK_ESTABLISHED) since start
    uint64_t totalDisconnects = 0;    // listener half: peers closed (LWS_CALLBACK_CLOSED) since start
    uint64_t rateLimitRejections = 0; // connection attempts rejected by AllowNewConnectionAttempt() since start
    uint64_t rxMessages = 0;
    uint64_t rxBytes = 0;
    uint64_t txMessages = 0;
    uint64_t txBytes = 0;
    size_t currentPeerCount = 0;      // live accepted peers right now (listener half)
};

class ScTransport {
public:
    ScTransport();
    ~ScTransport();

    // Must be called once before StartListening()/Connect(). acceptSubprotocol
    // is a parameter (not hard-coded past this point) so a future revision or
    // test build can override it, but every real caller must pass
    // "hub.bsc.bacnet.org" - see the file header and plan fact 1.
    void Configure(const ScTlsFiles& tls, const std::string& acceptSubprotocol);

    // Bounds how fast the LISTENER half accepts new inbound connection
    // ATTEMPTS - a token bucket refilling at `perSecond` tokens/second, burst
    // capacity `perSecond` (i.e. an idle listener can absorb a burst up to
    // the configured rate before it starts rejecting, then settles back to
    // steady-state `perSecond`/sec - see AllowNewConnectionAttempt() in the
    // .cpp). This is deliberately independent of - and enforced BEFORE - the
    // stack's own sc-max-hub-connections check (main.cpp's
    // g_scMaxHubConnections): that one bounds CONCURRENT connections at the
    // BACnet/SC protocol level, after a full TLS handshake; this one bounds
    // the RATE of new attempts at the raw-socket level, gated in
    // HandleServerCallback's LWS_CALLBACK_FILTER_NETWORK_CONNECTION case -
    // before TLS negotiation even starts, so a rejected attempt costs this
    // process almost nothing. 0 means "no limit" (the pre-existing,
    // unbounded behaviour). Safe to call before or after Configure()/
    // StartListening(); takes effect on the next FILTER_NETWORK_CONNECTION
    // callback. Connector-role (outbound) connections are NOT rate-limited -
    // this device controls when IT dials out, so there is no "someone else
    // hammering us" case to guard against on that half.
    void SetMaxConnectionAttemptsPerSecond(uint32_t perSecond);

    // --- Listener (server) half - real in this phase ---------------------

    // Starts (or, if already listening on a different URI, restarts) a TLS
    // WebSocket server on the host:port encoded in `uri` (wss://host:port/path;
    // the path is accepted but not otherwise interpreted - the stack does not
    // route by path). Requires Configure() to have been called with valid,
    // readable cert/key/CA files. Returns false (logs once) if the files are
    // missing/unreadable or the bind fails - the caller (ScTransportRouter, via
    // main.cpp's CallbackSCStartListening) is expected to retry every Tick, per
    // the stack's own retry contract for this callback (plan fact 6).
    bool StartListening(const std::string& uri);

    // Closes every accepted peer on `uri` and destroys the listening context.
    // Safe to call when not listening (no-op). This does NOT itself call
    // BACnetStack_SetBACnetSCWebSocketStatus for the evicted peers - main.cpp's
    // CallbackSCStopListening is only ever invoked by the stack when IT has
    // already decided to tear the peers down, so no further status report is
    // owed back to it.
    void StopListening(const std::string& uri);

    bool IsListening() const;
    const std::string& ListenUri() const { return m_listenUri; }

    // Snapshot of the cumulative counters above - see ScTransportMetrics'
    // comment. Cheap (a handful of integer copies plus m_peers.size()); safe
    // to call every tick (the 'health' keypress) or on every HTTP GET
    // /health request (Task 3).
    ScTransportMetrics GetMetrics() const;

    // --- Connector (client) half - real in this phase ---------------------

    // Opens (or, if one is already open/opening/closed-but-not-yet-retried for
    // this exact URI, tears down and REPLACES) an outbound TLS WebSocket
    // client connection to `uri` (wss://host:port/path), using ONE dedicated
    // client lws_context for this connection (plan's Connector subsection).
    // Requires Configure() to have been called with valid, readable
    // cert/key/CA files - this device presents the SAME identity as the
    // listener half (a BACnet/SC device has one identity regardless of role).
    // Returns false (logs) immediately if not configured, the cert files are
    // missing/unreadable, `uri` does not parse, or lws fails to create the
    // context/start the connection attempt. A `true` return means the
    // connection ATTEMPT started, not that it succeeded - watch for a queued
    // Connected(2)/Error(4) ScStatusEvent for that (see ScStatusEvent's
    // comment above). Per plan fact 7, this class never calls Connect() again
    // on its own after a failure/close - only the caller (ultimately the
    // stack's own retry timer, via main.cpp's CallbackInitiateWebsocket) does.
    bool Connect(const std::string& uri);

    // Closes a connection identified by `connStr`, which may be either an
    // outbound URI (as passed to Connect()) or an accepted-peer
    // "<acceptUri>|client=N" string (the listener half, Phase 2) - a single
    // lookup tries the accepted-peer table first, then the outbound-connection
    // table, and closes whichever one matches. Safe to call for an
    // unknown/already-closed connString (no-op). Does not itself push a
    // status event - the resulting LWS_CALLBACK_CLIENT_CLOSED/
    // LWS_CALLBACK_CLOSED callback does that once the close completes.
    void Disconnect(const std::string& connStr);

    // --- Shared --------------------------------------------------------

    // Enqueues `data` (len bytes) for the peer identified by `connStr` (an
    // accepted-peer string "<acceptUri>|client=N" for the listener half) and
    // asks lws to call back when the socket is writable. Returns false
    // immediately (0 bytes queued) if connStr names no live peer/connection -
    // ScTransportRouter's SendMessageForPort callback returns 0 to the stack
    // in that case, per CASBACnetStackDLL.h's SendMessageForPort contract.
    bool Send(const std::string& connStr, const uint8_t* data, uint16_t len);

    // Pumps every live lws_context non-blockingly (Phase 1 spike mechanism
    // (a)). Call once per main-loop tick, after BACnetStack_Tick(). May
    // populate the receive/status queues below; never calls BACnetStack_*.
    void Service();

    // Pops one reassembled frame (FIFO). Returns false if the queue is empty.
    bool PopReceived(ScReceivedFrame* outFrame);

    // Pops one status event (FIFO). Returns false if the queue is empty.
    bool PopStatusEvent(ScStatusEvent* outEvent);

    // --- lws callback trampoline entry points -----------------------------
    // Public only because each must be reachable from a free (non-member) C
    // function pointer handed to lws (struct lws_protocols::callback); not
    // meant to be called by application code. See ScTransport.cpp. Two
    // separate entry points (not one) because the listener's lws_context and
    // every connector lws_context are distinct contexts, each with its own
    // protocols table/callback - reasons like ESTABLISHED/CLOSED mean
    // different things (accept vs. dial) on each, so keeping them as two
    // functions (sharing the fragment-reassembly logic via
    // HandleIncomingFragment below) is clearer than one function branching
    // internally on every case.
    int HandleServerCallback(lws* wsi, int reason, void* user, void* in, std::size_t len);
    int HandleClientCallback(lws* wsi, int reason, void* user, void* in, std::size_t len);

private:
    struct PeerConnection {
        lws* wsi = nullptr;
        std::string connectionString;     // "<acceptUri>|client=N"
        std::string peerAddress;           // "ip:port" (best-effort - see PeerAddressPort() in the .cpp), captured
                                            // once at ESTABLISHED and reused at CLOSED (the socket may no longer
                                            // answer lws_get_peer_simple()/getpeername() by the time CLOSED fires)
        std::vector<uint8_t> rxAssembly;   // in-progress reassembly for this peer
        bool rxOverflow = false;           // true once rxAssembly exceeded the 1600B ceiling
        std::deque<std::vector<uint8_t>> txQueue;  // pending frames, each padded with LWS_PRE
        uint16_t lastCloseCode = 0;        // from LWS_CALLBACK_WS_PEER_INITIATED_CLOSE, if any
    };

    // One outbound (connector-role) connection: its own dedicated lws_context
    // (plan's Connector subsection - "one client lws_context per connection"),
    // keyed by the URI string Connect() was called with (m_clients' key, not a
    // member here - see Send()/Disconnect()'s lookups). Otherwise the same
    // shape as PeerConnection, reused via HandleIncomingFragment below.
    struct ClientConnection {
        lws_context* context = nullptr;
        lws* wsi = nullptr;                // null before ESTABLISHED and after CLOSED/error
        std::string uri;
        std::string peerAddress;           // "ip:port" the URI actually resolved/connected to - best-effort,
                                            // see PeerAddressPort() in the .cpp; lower priority than the
                                            // listener half (the connector already knows what it dialed)
        std::vector<uint8_t> rxAssembly;
        bool rxOverflow = false;
        std::deque<std::vector<uint8_t>> txQueue;
        uint16_t lastCloseCode = 0;
    };

    void LogListenFailureOnce(const std::string& reason);
    void DestroyListenerContext();
    PeerConnection* FindPeerByWsi(lws* wsi);

    // Refills the token bucket by elapsed time, then consumes one token if
    // available. Returns true (attempt allowed) when rate-limiting is
    // disabled (m_maxConnAttemptsPerSecond == 0) or a token was available;
    // false (attempt must be rejected) otherwise. See
    // SetMaxConnectionAttemptsPerSecond's comment above for the algorithm.
    bool AllowNewConnectionAttempt();

    // Builds m_clientProtocols on first use (every ClientConnection's
    // lws_context shares this one read-only table - lws only requires it stay
    // valid for each context's lifetime, not that it be unique per context).
    void EnsureClientProtocolsTable();
    // Destroys `conn`'s lws_context if it has one. Only ever called OUTSIDE
    // that context's own callback (from Connect(), replacing a stale entry
    // for the same URI, or from ~ScTransport()) - lws_context_destroy is not
    // reentrant-safe from inside its own callback, which is why
    // HandleClientCallback below never calls this itself.
    void DestroyClientContext(ClientConnection& conn);

    // Shared by LWS_CALLBACK_RECEIVE (server) and LWS_CALLBACK_CLIENT_RECEIVE
    // (client) - binary-frame enforcement, reassembly and the 1600-byte
    // ingress ceiling are IDENTICAL rules for both roles (plan: "reuse that
    // logic, don't duplicate/diverge it"). `destConnStr` is the bare accept
    // URI for a listener-side frame, or empty for a connector-side one (see
    // ScReceivedFrame's comment). Returns true if the frame handling requires
    // closing the socket (a close reason has already been set via
    // lws_close_reason - the caller must `return -1` from its own callback);
    // false otherwise (rxAssembly/rxOverflow updated in place, and a complete
    // frame - if any - already pushed to m_rxQueue).
    bool HandleIncomingFragment(lws* wsi, const void* in, std::size_t len,
                                const std::string& sourceConnStr, const std::string& destConnStr,
                                std::vector<uint8_t>* rxAssembly, bool* rxOverflow);

    // Shared by LWS_CALLBACK_SERVER_WRITEABLE (server) and
    // LWS_CALLBACK_CLIENT_WRITEABLE (client) - pops and writes exactly one
    // queued frame, updates the tx counters, and re-arms for another turn if
    // more frames remain (code-review finding: these two cases were
    // near-identical copy-paste, ~200 lines apart, nothing keeping them in
    // sync). `label` is the fully-formatted "who" clause for the short/
    // failed-write error message (e.g. "\"<connStr>\"" for the server half,
    // "hub \"<uri>\"" for the client half - the two callers' only real
    // wording difference, preserved verbatim rather than reconstructed
    // here). Returns true if the write failed and the caller must `return
    // -1` to close the socket;
    // false otherwise (including the "queue was already empty" no-op case).
    bool FlushOneQueuedFrame(lws* wsi, std::deque<std::vector<uint8_t>>* txQueue, const std::string& label);

    ScTlsFiles m_tls;
    std::string m_acceptSubprotocol;
    bool m_configured = false;

    lws_context* m_listenerContext = nullptr;
    std::string m_listenUri;
    uint64_t m_nextClientId = 1;

    // Heap-allocated (not a fixed-size member array) so this header does not
    // need the full `struct lws_protocols` definition - see the forward
    // declarations above. m_protocols (listener): allocated in
    // StartListening(), freed in DestroyListenerContext(); must outlive
    // m_listenerContext (lws keeps the pointer for the vhost's lifetime).
    // m_clientProtocols (connector): allocated once in
    // EnsureClientProtocolsTable(), freed in ~ScTransport(); shared by every
    // ClientConnection's context (see that method's comment).
    lws_protocols* m_protocols = nullptr;
    lws_protocols* m_clientProtocols = nullptr;
    std::string m_protocolNameStorage;  // backing storage for m_protocols[0].name AND m_clientProtocols[0].name - set once, in Configure()

    std::map<lws*, PeerConnection> m_peers;              // keyed by lws* (server half)
    std::map<std::string, lws*> m_connStringToWsi;        // connStr -> wsi, for Send()/Disconnect() lookup (server half)
    std::map<std::string, ClientConnection> m_clients;    // uri -> connection (connector half); std::map keeps references stable across inserts elsewhere in the map, which is why ccinfo.opaque_user_data can point directly at a map value (see ScTransport.cpp's Connect())

    std::deque<ScReceivedFrame> m_rxQueue;
    std::deque<ScStatusEvent> m_statusQueue;

    bool m_loggedListenFailure = false;  // avoid spamming retry logs every Tick

    // Permanent, process-lifetime latches (listener and connector sides
    // separately): once lws_create_context() has failed once for a role, it
    // is never called again for that role. See the comment at the top of
    // ScTransport.cpp (just above FileReadable()) for the full story of why
    // this is a permanent latch rather than a retry cooldown - a cooldown
    // was tried first and empirically disproved (the crash reproduces even
    // with a multi-second gap between attempts, so this isn't a rate issue).
    bool m_haveAttemptedListenCreateContext = false;
    bool m_haveAttemptedConnectCreateContext = false;
    // Both separate from m_loggedListenFailure/the connector's own bare
    // fprintf calls: once m_haveAttempted*CreateContext latches true, the
    // "refusing to retry" branch is reached on EVERY subsequent call (the
    // stack retries every Tick) - without a dedicated one-shot flag here,
    // that message would spam forever instead of printing once. Deliberately
    // NOT reusing m_loggedListenFailure for the listener's message: that flag
    // already latches true from the ORIGINAL failure's own log line, which
    // would silently suppress this distinct, later message if reused.
    bool m_loggedListenCreateContextRefusal = false;
    bool m_loggedConnectCreateContextRefusal = false;

    // Rate-limit token bucket state (listener half only) - see
    // SetMaxConnectionAttemptsPerSecond()/AllowNewConnectionAttempt() above.
    // 0 = disabled (the default, matching this class's pre-existing
    // unbounded behaviour until main.cpp opts in).
    uint32_t m_maxConnAttemptsPerSecond = 0;
    double m_rateLimitTokens = 0.0;
    std::chrono::steady_clock::time_point m_rateLimitLastRefill;

    // Cumulative metrics counters (Task 2/3, this batch) - see
    // ScTransportMetrics' comment for what each one means and when it is
    // incremented (ScTransport.cpp: LWS_CALLBACK_ESTABLISHED/CLOSED,
    // AllowNewConnectionAttempt(), HandleIncomingFragment(), and the
    // SERVER_WRITEABLE/CLIENT_WRITEABLE write paths).
    uint64_t m_totalConnects = 0;
    uint64_t m_totalDisconnects = 0;
    uint64_t m_rateLimitRejections = 0;
    uint64_t m_rxMessages = 0;
    uint64_t m_rxBytes = 0;
    uint64_t m_txMessages = 0;
    uint64_t m_txBytes = 0;
};

}  // namespace CASSc
