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
//   * Listener  (hub function "accept" role) - THIS PHASE implements it fully.
//     StartListening()/StopListening() open/close a server lws_context that
//     accepts mutually-authenticated TLS 1.3 WebSocket connections offering the
//     "hub.bsc.bacnet.org" subprotocol (135-2024 AB.7.1 - NOT "hub.bacnet.org",
//     see docs/bacnet-sc-transport-plan.md fact 1).
//   * Connector (hub/node "initiate" role) - interface declared here so the
//     class shape does not change in Phase 3, but Connect()/Disconnect() are
//     STUBS in this phase: they log and return false/no-op. Do not rely on
//     them yet.
//
// THREADING / RE-ENTRANCY (plan fact 6): every method here runs on the caller's
// thread (the main loop's thread, single-threaded in this example) and every
// libwebsockets callback also runs synchronously on that SAME thread, inside
// Service(). None of the lws callback handlers below call BACnetStack_* - they
// only touch the queues (m_rxQueue, m_statusQueue) and lws itself. The stack is
// told about received frames and status changes only when the MAIN LOOP later
// drains those queues via PopReceived()/PopStatusEvent() - never synchronously
// from inside a callback, even though lws itself can invoke a callback
// re-entrantly (e.g. from inside Connect(), see BACnetSCStartListening's own
// synchronous-callback note in main.cpp). This is what makes that safe.
//
// NON-BLOCKING SERVICE (plan fact 9 / Phase 1 spike finding): Service() pumps
// each live lws_context with `lws_cancel_service(ctx); lws_service(ctx, 0);` -
// mechanism (a) from docs/bacnet-sc-transport-plan.md, confirmed non-blocking
// on Windows by the Phase 1 spike (sc_transport_spike.cpp, now removed).
//
// INGRESS CEILING (plan fact 8): BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH is
// 1497 bytes. A reassembled WebSocket message larger than that is discarded
// and logged here - it is never handed to PopReceived()/the stack.
// =============================================================================

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
// Connected=2, Disconnected=3, Error=4). This class only ever queues
// Disconnected/Error for an accepted peer (never Connecting/Connected - an
// accepted socket does not become a "connection" the stack tracks until its
// own Connect-Request/Accept exchange finishes, which the stack, not this
// transport, is responsible for - see docs/bacnet-sc-transport-plan.md open
// risk #7).
struct ScStatusEvent {
    std::string uri;
    uint8_t status;      // BACnetSCConstants::BACnetSCWebsocketStatus (Connecting=1..Error=4)
    uint32_t closeCode;  // WebSocket close code if known, else 0
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

    // --- Connector (client) half - INTERFACE ONLY this phase -------------
    // Declared now so ScTransportRouter/main.cpp can be wired against the
    // final class shape; Phase 3 replaces the STUB bodies in ScTransport.cpp.
    // Do not call these expecting a real outbound connection yet.
    bool Connect(const std::string& uri);
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

    // --- lws callback trampoline entry point ------------------------------
    // Public only because it must be reachable from a free (non-member) C
    // function pointer handed to lws (struct lws_protocols::callback); not
    // meant to be called by application code. See ScTransport.cpp.
    int HandleServerCallback(lws* wsi, int reason, void* user, void* in, std::size_t len);

private:
    struct PeerConnection {
        lws* wsi = nullptr;
        std::string connectionString;     // "<acceptUri>|client=N"
        std::vector<uint8_t> rxAssembly;   // in-progress reassembly for this peer
        bool rxOverflow = false;           // true once rxAssembly exceeded the 1497B ceiling
        std::deque<std::vector<uint8_t>> txQueue;  // pending frames, each padded with LWS_PRE
        uint16_t lastCloseCode = 0;        // from LWS_CALLBACK_WS_PEER_INITIATED_CLOSE, if any
    };

    void LogListenFailureOnce(const std::string& reason);
    void DestroyListenerContext();
    PeerConnection* FindPeerByWsi(lws* wsi);

    ScTlsFiles m_tls;
    std::string m_acceptSubprotocol;
    bool m_configured = false;

    lws_context* m_listenerContext = nullptr;
    std::string m_listenUri;
    uint64_t m_nextClientId = 1;

    // Heap-allocated (not a fixed-size member array) so this header does not
    // need the full `struct lws_protocols` definition - see the forward
    // declarations above. Allocated in StartListening(), freed in
    // DestroyListenerContext(); must outlive m_listenerContext (lws keeps the
    // pointer for the vhost's lifetime).
    lws_protocols* m_protocols = nullptr;
    std::string m_protocolNameStorage;  // backing storage for m_protocols[0].name

    std::map<lws*, PeerConnection> m_peers;              // keyed by lws* (server half)
    std::map<std::string, lws*> m_connStringToWsi;        // connStr -> wsi, for Send() lookup

    std::deque<ScReceivedFrame> m_rxQueue;
    std::deque<ScStatusEvent> m_statusQueue;

    bool m_loggedListenFailure = false;  // avoid spamming retry logs every Tick
};

}  // namespace CASSc
