// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
#pragma once

// ScTransport.h
// =============================================================================
// A thin libwebsockets(+OpenSSL) wrapper that supplies the raw WebSocket/TLS
// transport BACnet/SC needs. The CAS BACnet Stack owns the BACnet/SC PROTOCOL
// (Hello handshake, the hub function's state machine, BVLC framing) - see
// main.cpp's file header - and asks the host for a transport through
// callbacks. This class IS that transport for the one role a B-SCHUB hub
// needs: the hub function's LISTENER ("accept" role).
//
// StartListening()/StopListening() open/close a server lws_context that
// accepts mutually-authenticated TLS 1.3 WebSocket connections offering the
// "hub.bsc.bacnet.org" subprotocol (135-2024 AB.7.1 - see sc_transport/README.md
// fact 1).
//
// THREADING / RE-ENTRANCY (README fact 6): every method here runs on the
// caller's thread (the main loop's thread, single-threaded in this example)
// and every libwebsockets callback also runs synchronously on that SAME thread,
// inside Service(). HandleServerCallback below never calls BACnetStack_* - it
// only touches the queues (m_rxQueue, m_statusQueue) and lws itself. The stack
// is told about received frames and status changes only when the MAIN LOOP
// later drains those queues via PopReceived()/PopStatusEvent() - never
// synchronously from inside a callback.
//
// NON-BLOCKING SERVICE: Service() pumps the listener's lws_context with
// `lws_cancel_service(ctx); lws_service(ctx, 0);`, which returns at once on
// Windows and Linux.
//
// NO TIMERS OF ITS OWN (README fact 7): the stack owns every timer - heartbeat,
// Connect-Request timeouts. This class only moves bytes and reports closes.
//
// INGRESS CEILING (README fact 8): BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH is
// 1600 bytes, ANSI/ASHRAE 135 Annex AB's minimum BVLC-SC relay size. A
// reassembled WebSocket message larger than that is discarded and logged here
// - it is never handed to PopReceived()/the stack.
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

// PEM file paths for the hub's TLS identity: its own operational certificate
// + private key, plus the CA bundle used to validate the peer. The listener
// requires all three (mutual TLS - AB requires a conformant SC node to present
// a client certificate); see cert_tool.h for how the hub gets them from a
// Certificate Authority.
struct ScTlsFiles {
    std::string caCertPath;    // the trusted issuers - validate the PEER's certificate
    std::string certPath;      // this device's own operational certificate
    std::string keyPath;       // this device's own private key (never shared)
    // Optional certificate revocation list(s), PEM. When this file exists, the
    // listener's TLS context loads it and checks the peer's certificate
    // against it (X509_V_FLAG_CRL_CHECK): a revoked certificate is refused,
    // and so is a certificate whose issuer has no CRL in the file, or whose
    // CRL has expired - revocation checking fails closed. A file that exists
    // but holds no parsable CRL stops the listener from starting (logged)
    // until it is fixed. Empty or missing = no revocation checking.
    std::string crlPath;
};

// One reassembled BACnet/SC BVLC message, plus who it came from/is addressed
// to, exactly as ScTransportRouter needs to hand to
// BACnetStack_RegisterCallbackReceiveMessageForPort's callback:
//   sourceConnectionString      - the accepted-peer string "<acceptUri>|client=N"
//                                 the stack should use as the SOURCE ADDRESS,
//                                 and later as the address to Send() a reply to
//                                 (README fact 2; matches DoesConfiguredUriMatch
//                                 in source/BACnetDataLinkSC.cpp).
//   destinationConnectionString - the bare accept URI.
struct ScReceivedFrame {
    std::string sourceConnectionString;
    std::string destinationConnectionString;
    std::vector<uint8_t> data;
};

// A connection-status change to report to the stack via
// BACnetStack_SetBACnetSCWebSocketStatus(uri, uriLength, status, closeCode).
// `status` uses BACnetSCConstants::BACnetSCWebsocketStatus exactly (README
// fact 3, source/BACnetSCConstants.h - Connecting=1, Connected=2,
// Disconnected=3, Error=4).
//
// For an ACCEPTED peer this class only ever queues Disconnected/Error (never
// Connecting/Connected): an accepted socket does not become a "connection" the
// stack tracks until its own Connect-Request/Accept exchange finishes, which
// the stack, not this transport, is responsible for.
struct ScStatusEvent {
    std::string uri;
    uint8_t status;      // BACnetSCConstants::BACnetSCWebsocketStatus (Connecting=1..Error=4)
    uint32_t closeCode;  // WebSocket close code if known, else 0
};

// Cumulative counters for the 'm' console key and the connection-limit
// warning in main.cpp. All counters are since process start. currentPeerCount
// is the live count of accepted sockets; acceptedPeerCount the ones the stack
// has accepted with a Connect-Accept. A message is counted once it is a
// complete, reassembled BVLC frame (RX) or once lws has actually written it to
// the socket (TX) - never a partial fragment.
struct ScTransportMetrics {
    uint64_t totalConnects = 0;       // peers accepted (LWS_CALLBACK_ESTABLISHED) since start
    uint64_t totalDisconnects = 0;    // peers closed (LWS_CALLBACK_CLOSED) since start
    uint64_t rateLimitRejections = 0; // connection attempts refused by either rate limit since start
    uint64_t rxMessages = 0;
    uint64_t rxBytes = 0;
    uint64_t txMessages = 0;
    uint64_t txBytes = 0;
    uint64_t txQueueOverflows = 0;    // connections closed because their transmit queue was full
    uint64_t connectRequestsRefused = 0; // Connect-Requests the stack answered with a NAK
    size_t acceptedPeerCount = 0;     // peers the stack has accepted (Connect-Accept sent)
    size_t currentPeerCount = 0;      // live accepted sockets right now
};

// The most frames Send() queues for one connection before it gives up on that
// peer. The stack hands every frame to SendMessageForPort and has no
// backpressure signal, so a peer that stops reading would otherwise make its
// queue grow without limit. 64 frames is far more than a healthy peer ever has
// waiting (each is at most 1600 bytes, so about 100 KiB per peer).
const std::size_t kMaxTxQueueFrames = 64;

class ScTransport {
public:
    ScTransport();
    ~ScTransport();

    // Must be called once before StartListening(). acceptSubprotocol is a
    // parameter so the one place that chooses it (main.cpp) is visible, but
    // every real caller must pass "hub.bsc.bacnet.org" - see the file header.
    void Configure(const ScTlsFiles& tls, const std::string& acceptSubprotocol);

    // Bounds how fast the listener accepts new inbound connection ATTEMPTS.
    // Two token buckets, both checked in HandleServerCallback's
    // LWS_CALLBACK_FILTER_NETWORK_CONNECTION case - before the TLS handshake
    // starts, so a refused attempt costs almost nothing:
    //
    //   perAddressPerSecond - one bucket PER SOURCE IP ADDRESS. A flooding
    //                         host drains only its own bucket, so it can't
    //                         starve well-behaved devices reconnecting from
    //                         other addresses. The table of addresses is
    //                         bounded (kMaxTrackedAddresses) and ages out:
    //                         an address whose bucket has refilled is
    //                         forgotten when room is needed.
    //   totalPerSecond      - one bucket for the whole listener, a ceiling on
    //                         a flood from many addresses at once.
    //
    // Each bucket refills at its rate and holds at most one second's worth
    // (so an idle listener absorbs a short burst, then settles to the rate).
    // 0 turns that limit off. This is separate from - and enforced before -
    // the stack's maximum-connections check, which bounds CONCURRENT
    // connections after a full handshake.
    void SetConnectionRateLimits(uint32_t perAddressPerSecond, uint32_t totalPerSecond);

    // Starts (or, if already listening on a different URI, restarts) a TLS
    // WebSocket server on the host:port encoded in `uri` (wss://host:port/path;
    // the path is accepted but not otherwise interpreted - the stack does not
    // route by path). Requires Configure() to have been called with valid,
    // readable cert/key/CA files. Returns false (logs once) if the files are
    // missing/unreadable or the bind fails - the stack calls it again every
    // Tick while it returns false (README fact 6).
    bool StartListening(const std::string& uri);

    // Closes every accepted peer on `uri` and destroys the listening context.
    // Safe to call when not listening (no-op). This does NOT itself call
    // BACnetStack_SetBACnetSCWebSocketStatus for the evicted peers - main.cpp's
    // CallbackSCStopListening is only ever invoked by the stack when IT has
    // already decided to tear the peers down, so no further status report is
    // owed back to it.
    void StopListening(const std::string& uri);

    bool IsListening() const;

    // Rebuilds the listener's TLS context so it loads the certificate/key/CA
    // files (and the CRL) again - called after new certificates were activated
    // over BACnet (main.cpp section 2d-ii), and when the CRL file changes. The
    // listener is torn down and restarted on the same URI: every accepted peer
    // is disconnected (reported to the stack as Disconnected, like any close)
    // and reconnects under the new certificates.
    void ReloadCredentials();
    const std::string& ListenUri() const { return m_listenUri; }

    // Snapshot of the cumulative counters above - see ScTransportMetrics'
    // comment. Cheap (a handful of integer copies plus m_peers.size()); safe
    // to call every tick.
    ScTransportMetrics GetMetrics() const;

    // Closes the accepted peer identified by `connStr` ("<acceptUri>|client=N").
    // Safe to call for an unknown/already-closed connString (no-op). Does not
    // itself push a status event - the resulting LWS_CALLBACK_CLOSED callback
    // does that once the close completes.
    void Disconnect(const std::string& connStr);

    // Enqueues `data` (len bytes) for the peer identified by `connStr` (an
    // accepted-peer string "<acceptUri>|client=N") and asks lws to call back
    // when the socket is writable. Returns false immediately (0 bytes queued)
    // if connStr names no live peer - ScTransportRouter's SendMessageForPort
    // callback returns 0 to the stack in that case, per CASBACnetStackDLL.h's
    // SendMessageForPort contract. Also returns false, and closes the
    // connection (logged, close code 1008), when that peer already has
    // kMaxTxQueueFrames frames waiting - a peer that has stopped reading. The
    // close is reported to the stack like any other.
    bool Send(const std::string& connStr, const uint8_t* data, uint16_t len);

    // Pumps the listener's lws_context non-blockingly. Call once per main-loop
    // tick, after BACnetStack_Tick(). May populate the receive/status queues
    // below; never calls BACnetStack_*.
    void Service();

    // Pops one reassembled frame (FIFO). Returns false if the queue is empty.
    bool PopReceived(ScReceivedFrame* outFrame);

    // Pops one status event (FIFO). Returns false if the queue is empty.
    bool PopStatusEvent(ScStatusEvent* outEvent);

    // --- lws callback trampoline entry point -------------------------------
    // Public only because it must be reachable from a free (non-member) C
    // function pointer handed to lws (struct lws_protocols::callback); not
    // meant to be called by application code. See ScTransport.cpp.
    int HandleServerCallback(lws* wsi, int reason, void* user, void* in, std::size_t len);

private:
    // A close this class asked for. lws only closes a connection when one of
    // its callbacks returns -1, so Disconnect() and a full transmit queue set
    // this and ask for a WRITEABLE callback, which sends the close frame.
    struct CloseRequest {
        bool requested = false;
        uint16_t code = 0;       // WebSocket close status, e.g. 1000 normal, 1008 policy violation
        std::string reason;
    };

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
        CloseRequest closeRequest;         // set by Disconnect()/a full txQueue; acted on when writable
        uint64_t clientId = 0;             // the N in "|client=N"
        std::string certificateSubject;    // the peer's TLS certificate subject (audit trail)
        std::string vmac;                  // from its Connect-Request (audit trail)
        std::string uuid;
        bool accepted = false;             // the stack sent it a Connect-Accept
    };

    void LogListenFailureOnce(const std::string& reason);
    void DestroyListenerContext();
    PeerConnection* FindPeerByWsi(lws* wsi);

    // Takes one token from `address`'s bucket and from the listener-wide
    // bucket. Returns false (the attempt must be refused) if either is empty;
    // *limitHit then says which ("per-address" or "total"). See
    // SetConnectionRateLimits().
    bool AllowNewConnectionAttempt(const std::string& address, const char** limitHit);

    // LWS_CALLBACK_RECEIVE: binary-frame enforcement, reassembly and the
    // 1600-byte ingress ceiling. `destConnStr` is the bare accept URI. Returns
    // true if the frame handling requires closing the socket (a close reason
    // has already been set via lws_close_reason - the caller must `return -1`
    // from its own callback); false otherwise (rxAssembly/rxOverflow updated
    // in place, and a complete frame - if any - already pushed to m_rxQueue).
    bool HandleIncomingFragment(lws* wsi, const void* in, std::size_t len,
                                const std::string& sourceConnStr, const std::string& destConnStr,
                                std::vector<uint8_t>* rxAssembly, bool* rxOverflow);

    // LWS_CALLBACK_SERVER_WRITEABLE: pops and writes exactly one queued frame,
    // updates the tx counters, and re-arms for another turn if more frames
    // remain. `label` names the peer in the short/failed-write error message.
    // Returns true if the write failed and the caller must `return -1` to
    // close the socket; false otherwise (including the "queue was already
    // empty" no-op case).
    bool FlushOneQueuedFrame(lws* wsi, std::deque<std::vector<uint8_t>>* txQueue, const std::string& label);

    // Queues one frame for a connection, or - if kMaxTxQueueFrames are already
    // waiting - drops its queue and asks for the connection to be closed.
    // Returns false in that case.
    bool EnqueueFrame(lws* wsi, std::deque<std::vector<uint8_t>>* txQueue, CloseRequest* closeRequest,
                      const std::string& label, const uint8_t* data, uint16_t len);

    // Audit trail: records the VMAC/UUID from an accepted peer's
    // Connect-Request, and logs once the stack answers it with Connect-Accept
    // (or refuses it). Called with every complete frame received from, or
    // sent to, that peer; ignores everything except those three messages.
    void AuditReceivedFrame(PeerConnection* peer, const std::vector<uint8_t>& frame);
    void AuditSentFrame(PeerConnection* peer, const uint8_t* data, uint16_t len);

    // Asks lws for a WRITEABLE callback that closes the connection with
    // `code`/`reason` (see CloseRequest). A no-op if a close is already pending.
    static void RequestClose(lws* wsi, CloseRequest* closeRequest, uint16_t code, const std::string& reason);

    // Called at the top of each WRITEABLE callback: if a close was requested,
    // sets lws's close reason and returns true - the caller then returns -1.
    // A normal close waits until `txQueue` is empty, so a frame the stack sent
    // just before asking for the close (a Connect-Request NAK, a
    // Disconnect-ACK) still reaches the peer; a 1008 close (the queue
    // overflowed) happens at once.
    static bool ApplyRequestedClose(lws* wsi, const CloseRequest& closeRequest,
                                    const std::deque<std::vector<uint8_t>>& txQueue);

    ScTlsFiles m_tls;
    std::string m_acceptSubprotocol;
    bool m_configured = false;

    lws_context* m_listenerContext = nullptr;
    std::string m_listenUri;
    // The URI the stack asked us to listen on (StartListening) and hasn't
    // asked us to stop (StopListening) - kept even while the listener is down,
    // so Service() can bring it back after a failed restart: the stack still
    // believes it is listening and won't ask again.
    std::string m_wantedListenUri;
    // Rate-limit refusals: when the last one was logged, and how many were
    // refused without a log line since then.
    std::chrono::steady_clock::time_point m_lastRateLimitLog;
    uint64_t m_rateLimitLogSuppressed = 0;
    uint64_t m_nextClientId = 1;

    // Heap-allocated (not a fixed-size member array) so this header does not
    // need the full `struct lws_protocols` definition - see the forward
    // declarations above. Allocated in StartListening(), freed in
    // DestroyListenerContext(); must outlive m_listenerContext (lws keeps the
    // pointer for the vhost's lifetime).
    lws_protocols* m_protocols = nullptr;
    std::string m_protocolNameStorage;  // backing storage for m_protocols[0].name

    std::map<lws*, PeerConnection> m_peers;              // keyed by lws*
    std::map<std::string, lws*> m_connStringToWsi;        // connStr -> wsi, for Send()/Disconnect() lookup

    std::deque<ScReceivedFrame> m_rxQueue;
    std::deque<ScStatusEvent> m_statusQueue;

    bool m_loggedListenFailure = false;  // avoid spamming retry logs every Tick

    // When lws_create_context() last failed for the listener; StartListening()
    // waits a few seconds before trying again (see ScTransport.cpp).
    std::chrono::steady_clock::time_point m_lastListenCreateFailure;

    // Rate-limit state - see SetConnectionRateLimits(). A rate of 0 means
    // that limit is off (the default until main.cpp sets it).
    struct TokenBucket {
        double tokens = 0.0;
        std::chrono::steady_clock::time_point lastRefill;
    };
    // The most source addresses tracked at once. When the table is full, the
    // addresses whose buckets have refilled (idle for a second or more) are
    // dropped; if none has, a new address is checked against the total limit
    // only, so the table itself can't be used to exhaust memory.
    static const std::size_t kMaxTrackedAddresses = 1024;
    uint32_t m_perAddressRateLimit = 0;
    uint32_t m_totalRateLimit = 0;
    TokenBucket m_totalBucket;
    std::map<std::string, TokenBucket> m_addressBuckets;

    // Cumulative counters - see ScTransportMetrics' comment for what each one
    // means and when it is incremented.
    uint64_t m_totalConnects = 0;
    uint64_t m_totalDisconnects = 0;
    uint64_t m_rateLimitRejections = 0;
    uint64_t m_connectRequestsRefused = 0;
    uint64_t m_rxMessages = 0;
    uint64_t m_rxBytes = 0;
    uint64_t m_txMessages = 0;
    uint64_t m_txBytes = 0;
    uint64_t m_txQueueOverflows = 0;
};

}  // namespace CASSc
