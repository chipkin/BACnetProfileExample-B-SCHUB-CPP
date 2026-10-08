// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
// Implementation of ScTransportRouter. See ScTransportRouter.h for the contract.
#include "ScTransportRouter.h"

#include "CASBACnetStackAdapter.h"

#include <cstdio>
#include <cstring>

namespace CASSc {

namespace {

// The stack calls CallbackReceiveMessageForPort/CallbackSendMessageForPort as
// plain C function pointers (no user-data argument - see
// common/CASExampleHelper.cpp's identical comment), so there is exactly one
// active router per process. This example only ever constructs one
// (in main.cpp), so that is not a real limitation.
ScTransportRouter* g_activeRouter = nullptr;

uint16_t TrampolineReceiveMessage(uint8_t* message, const uint16_t maxMessageLength,
                                  uint8_t* sourceConnectionString, uint8_t* sourceConnectionStringLength,
                                  uint8_t* destinationConnectionString, uint8_t* destinationConnectionStringLength,
                                  const uint8_t maxConnectionStringLength, uint32_t* networkPortInstance) {
    if (g_activeRouter == nullptr) {
        return 0;
    }
    return g_activeRouter->HandleReceiveMessage(message, maxMessageLength, sourceConnectionString,
                                                sourceConnectionStringLength, destinationConnectionString,
                                                destinationConnectionStringLength, maxConnectionStringLength,
                                                networkPortInstance);
}

uint16_t TrampolineSendMessage(const uint8_t* message, const uint16_t messageLength,
                               const uint8_t* connectionString, const uint8_t connectionStringLength,
                               const uint32_t networkPortInstance, const bool broadcast) {
    if (g_activeRouter == nullptr) {
        return 0;
    }
    return g_activeRouter->HandleSendMessage(message, messageLength, connectionString, connectionStringLength,
                                             networkPortInstance, broadcast);
}

}  // namespace

ScTransportRouter::ScTransportRouter(const uint32_t scNetworkPortInstance, ScTransport& transport)
    : m_scNetworkPortInstance(scNetworkPortInstance), m_transport(transport) {}

ScTransportRouter::~ScTransportRouter() {
    if (g_activeRouter == this) {
        g_activeRouter = nullptr;
    }
}

void ScTransportRouter::RegisterCallbacks() {
    g_activeRouter = this;
    BACnetStack_RegisterCallbackReceiveMessageForPort(&TrampolineReceiveMessage);
    BACnetStack_RegisterCallbackSendMessageForPort(&TrampolineSendMessage);
}

void ScTransportRouter::DrainStatusEvents() {
    ScStatusEvent evt;
    while (m_transport.PopStatusEvent(&evt)) {
        const bool accepted = BACnetStack_SetBACnetSCWebSocketStatus(
            evt.uri.c_str(), (uint16_t)evt.uri.size(), evt.status, evt.closeCode);
        if (!accepted) {
            // Normal, not an error: the stack may never have registered this
            // peer (e.g. it disconnected before completing Connect-Request/
            // Accept) or may have already forgotten it (e.g. StopListening was
            // already processed).
            printf("FYI: BACnetStack_SetBACnetSCWebSocketStatus(\"%s\", status=%u) was not accepted "
                   "- the stack does not (or no longer) know this peer; not an error.\n",
                   evt.uri.c_str(), (unsigned)evt.status);
        }
    }
}

uint16_t ScTransportRouter::HandleReceiveMessage(uint8_t* message, const uint16_t maxMessageLength,
                                                 uint8_t* sourceConnectionString, uint8_t* sourceConnectionStringLength,
                                                 uint8_t* destinationConnectionString, uint8_t* destinationConnectionStringLength,
                                                 const uint8_t maxConnectionStringLength, uint32_t* networkPortInstance) {
    ScReceivedFrame frame;
    if (!m_transport.PopReceived(&frame)) {
        return 0;
    }

    if (frame.data.size() > maxMessageLength) {
        // Should not happen - ScTransport already enforces the 1600-byte
        // ingress ceiling (README fact 8) - but never overrun the stack's
        // buffer regardless of why this frame is larger than it expects.
        fprintf(stderr, "BACnet/SC: dropping %zu-byte frame from \"%s\" - exceeds the stack's "
                        "receive buffer (%u bytes)\n", frame.data.size(), frame.sourceConnectionString.c_str(),
                (unsigned)maxMessageLength);
        return 0;
    }
    if (frame.sourceConnectionString.size() > maxConnectionStringLength ||
        frame.destinationConnectionString.size() > maxConnectionStringLength) {
        fprintf(stderr, "BACnet/SC: dropping frame - connection string too long for the stack's buffer "
                        "(source \"%s\", %zu bytes; max %u)\n", frame.sourceConnectionString.c_str(),
                frame.sourceConnectionString.size(), (unsigned)maxConnectionStringLength);
        return 0;
    }

    printf("RX %u bytes from SC peer \"%s\" (Network Port %u)\n", (unsigned)frame.data.size(),
           frame.sourceConnectionString.c_str(), (unsigned)m_scNetworkPortInstance);

    if (!frame.data.empty()) {
        memcpy(message, frame.data.data(), frame.data.size());
    }
    memcpy(sourceConnectionString, frame.sourceConnectionString.data(), frame.sourceConnectionString.size());
    *sourceConnectionStringLength = (uint8_t)frame.sourceConnectionString.size();
    if (destinationConnectionString != NULL && destinationConnectionStringLength != NULL) {
        memcpy(destinationConnectionString, frame.destinationConnectionString.data(),
               frame.destinationConnectionString.size());
        *destinationConnectionStringLength = (uint8_t)frame.destinationConnectionString.size();
    }
    *networkPortInstance = m_scNetworkPortInstance;
    return (uint16_t)frame.data.size();
}

uint16_t ScTransportRouter::HandleSendMessage(const uint8_t* message, const uint16_t messageLength,
                                              const uint8_t* connectionString, const uint8_t connectionStringLength,
                                              const uint32_t networkPortInstance, const bool broadcast) {
    (void)broadcast;  // BACnet/SC: the stack has already chosen the connection(s) to send to
    if (networkPortInstance == m_scNetworkPortInstance) {
        const std::string connStr(reinterpret_cast<const char*>(connectionString), connectionStringLength);
        const bool ok = m_transport.Send(connStr, message, messageLength);
        // SC SendMessage must return EXACTLY messageLength on success, 0
        // otherwise (CASBACnetStackDLL.h's SendMessageForPort contract for SC
        // paths - sc_transport/README.md fact 4).
        printf("TX %u bytes to SC peer \"%s\" (Network Port %u)%s\n", ok ? (unsigned)messageLength : 0u,
               connStr.c_str(), (unsigned)networkPortInstance, ok ? "" : " - FAILED (unknown/closed peer)");
        return ok ? messageLength : 0;
    }

    return 0;  // not the BACnet/SC port - not this router's to answer
}

}  // namespace CASSc
