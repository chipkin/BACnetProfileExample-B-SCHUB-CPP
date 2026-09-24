// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
// Implementation of ScTransportRouter. See ScTransportRouter.h for the contract.
#include "ScTransportRouter.h"

#include "CASExampleHelper.h"
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

ScTransportRouter::ScTransportRouter(const uint32_t ipNetworkPortInstance, const uint32_t scNetworkPortInstance,
                                     ScTransport& transport)
    : m_ipNetworkPortInstance(ipNetworkPortInstance), m_scNetworkPortInstance(scNetworkPortInstance),
      m_transport(transport) {}

ScTransportRouter::~ScTransportRouter() {
    if (g_activeRouter == this) {
        g_activeRouter = nullptr;
    }
    Shutdown();
}

bool ScTransportRouter::Start(const uint16_t udpPort) {
    if (!m_udp.Connect(udpPort)) {
        printf("Error: ScTransportRouter: failed to bind UDP port %u (Network Port %u).\n",
               (unsigned)udpPort, (unsigned)m_ipNetworkPortInstance);
        return false;
    }
    m_udpPort = udpPort;
    m_udpBound = true;
    printf("FYI: Listening for BACnet/IP on UDP port %u (Network Port %u).\n",
           (unsigned)udpPort, (unsigned)m_ipNetworkPortInstance);
    return true;
}

void ScTransportRouter::RegisterCallbacks() {
    g_activeRouter = this;
    BACnetStack_RegisterCallbackReceiveMessageForPort(&TrampolineReceiveMessage);
    BACnetStack_RegisterCallbackSendMessageForPort(&TrampolineSendMessage);
}

void ScTransportRouter::Shutdown() {
    if (m_udpBound) {
        m_udp.Disconnect();
        m_udpBound = false;
    }
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
            // already processed) - see the plan's ScTransportRouter subsection.
            printf("FYI: BACnetStack_SetBACnetSCWebSocketStatus(\"%s\", status=%u) was not accepted "
                   "- the stack does not (or no longer) know this peer; not an error.\n",
                   evt.uri.c_str(), (unsigned)evt.status);
        }
    }
}

void ScTransportRouter::SendIAm(const uint32_t deviceInstance) {
    // Same local-subnet-broadcast computation as CASExampleHelper::SendIAm
    // (CASExampleHelper.cpp) - reimplemented here because that function only
    // knows about CASExampleHelper's OWN UDP bindings (this router keeps its
    // IP socket separately - see the class header comment).
    uint8_t bcast[4] = { 255, 255, 255, 255 };
    uint8_t ip[4];
    uint8_t mask[4];
    if (CASExampleHelper::GetLocalIPv4(ip, mask)) {
        bcast[0] = (uint8_t)(ip[0] | ~mask[0]);
        bcast[1] = (uint8_t)(ip[1] | ~mask[1]);
        bcast[2] = (uint8_t)(ip[2] | ~mask[2]);
        bcast[3] = (uint8_t)(ip[3] | ~mask[3]);
    }

    const uint8_t connectionString[6] = {
        bcast[0], bcast[1], bcast[2], bcast[3],
        (uint8_t)((m_udpPort >> 8) & 0xFF), (uint8_t)(m_udpPort & 0xFF)
    };
    BACnetStack_SendIAm(deviceInstance, connectionString, 6, m_ipNetworkPortInstance,
                        true /*broadcast*/, 0 /*local network*/, NULL, 0);
}

uint16_t ScTransportRouter::HandleReceiveMessage(uint8_t* message, const uint16_t maxMessageLength,
                                                 uint8_t* sourceConnectionString, uint8_t* sourceConnectionStringLength,
                                                 uint8_t* destinationConnectionString, uint8_t* destinationConnectionStringLength,
                                                 const uint8_t maxConnectionStringLength, uint32_t* networkPortInstance) {
    // Alternate which side is polled first so a busy IP link cannot starve SC
    // (or vice versa) - see the header comment and plan's "alternate IP-first/
    // SC-first each Tick" note. Flip on every call, not just every Tick: the
    // stack calls this repeatedly per Tick until it returns 0, so flipping per
    // call is the finer-grained version of the same fairness goal.
    m_pollIpFirst = !m_pollIpFirst;

    if (m_pollIpFirst) {
        const uint16_t fromIp = ReceiveFromIp(message, maxMessageLength, sourceConnectionString,
                                              sourceConnectionStringLength, maxConnectionStringLength,
                                              networkPortInstance);
        if (fromIp > 0) {
            return fromIp;
        }
        // destinationConnectionString/Length are left untouched for IP - see
        // common/CASExampleHelper.cpp's identical (void)-cast of them: the
        // stack does not need them for a unicast/broadcast IP receive.
        return ReceiveFromSc(message, maxMessageLength, sourceConnectionString, sourceConnectionStringLength,
                             destinationConnectionString, destinationConnectionStringLength,
                             maxConnectionStringLength, networkPortInstance);
    }

    const uint16_t fromSc = ReceiveFromSc(message, maxMessageLength, sourceConnectionString,
                                          sourceConnectionStringLength, destinationConnectionString,
                                          destinationConnectionStringLength, maxConnectionStringLength,
                                          networkPortInstance);
    if (fromSc > 0) {
        return fromSc;
    }
    return ReceiveFromIp(message, maxMessageLength, sourceConnectionString, sourceConnectionStringLength,
                         maxConnectionStringLength, networkPortInstance);
}

uint16_t ScTransportRouter::ReceiveFromIp(uint8_t* message, const uint16_t maxMessageLength,
                                          uint8_t* sourceConnectionString, uint8_t* sourceConnectionStringLength,
                                          const uint8_t maxConnectionStringLength, uint32_t* networkPortInstance) {
    if (!m_udpBound || maxConnectionStringLength < 6) {
        return 0;
    }
    uint8_t fromIp[4] = { 0, 0, 0, 0 };
    uint16_t fromPort = 0;
    const uint16_t bytesRead = m_udp.Receive(message, maxMessageLength, fromIp, &fromPort);
    if (bytesRead == 0) {
        return 0;
    }

    // Same RX log line format as common/CASExampleHelper.cpp's
    // HelperReceiveMessage, for a consistent log across every example in the
    // series (this router's own IP path, not common's - see the class header).
    printf("RX %u bytes from %u.%u.%u.%u:%u (Network Port %u)\n", (unsigned)bytesRead,
           fromIp[0], fromIp[1], fromIp[2], fromIp[3], (unsigned)fromPort,
           (unsigned)m_ipNetworkPortInstance);

    sourceConnectionString[0] = fromIp[0];
    sourceConnectionString[1] = fromIp[1];
    sourceConnectionString[2] = fromIp[2];
    sourceConnectionString[3] = fromIp[3];
    sourceConnectionString[4] = (uint8_t)((fromPort >> 8) & 0xFF);
    sourceConnectionString[5] = (uint8_t)(fromPort & 0xFF);
    *sourceConnectionStringLength = 6;
    *networkPortInstance = m_ipNetworkPortInstance;
    return bytesRead;
}

uint16_t ScTransportRouter::ReceiveFromSc(uint8_t* message, const uint16_t maxMessageLength,
                                          uint8_t* sourceConnectionString, uint8_t* sourceConnectionStringLength,
                                          uint8_t* destinationConnectionString, uint8_t* destinationConnectionStringLength,
                                          const uint8_t maxConnectionStringLength, uint32_t* networkPortInstance) {
    ScReceivedFrame frame;
    if (!m_transport.PopReceived(&frame)) {
        return 0;
    }

    if (frame.data.size() > maxMessageLength) {
        // Should not happen - ScTransport already enforces the 1600-byte
        // ingress ceiling (plan fact 8) - but never overrun the stack's
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
    if (networkPortInstance == m_ipNetworkPortInstance) {
        if (!m_udpBound || connectionStringLength < 6) {
            return 0;
        }
        const uint8_t ip[4] = { connectionString[0], connectionString[1], connectionString[2], connectionString[3] };
        const uint16_t port = (uint16_t)((connectionString[4] << 8) | connectionString[5]);
        const uint16_t sent = m_udp.Send(ip, port, message, messageLength);
        // Same TX log line format as common/CASExampleHelper.cpp's HelperSendMessage.
        printf("TX %u bytes to %u.%u.%u.%u:%u%s (Network Port %u)\n", (unsigned)sent,
               ip[0], ip[1], ip[2], ip[3], (unsigned)port, broadcast ? " (broadcast)" : "",
               (unsigned)networkPortInstance);
        return sent;
    }

    if (networkPortInstance == m_scNetworkPortInstance) {
        const std::string connStr(reinterpret_cast<const char*>(connectionString), connectionStringLength);
        const bool ok = m_transport.Send(connStr, message, messageLength);
        // SC SendMessage must return EXACTLY messageLength on success, 0
        // otherwise (CASBACnetStackDLL.h's SendMessageForPort contract for SC
        // paths, CAS BACnet Stack issue #1569 - plan fact 4).
        printf("TX %u bytes to SC peer \"%s\" (Network Port %u)%s\n", ok ? (unsigned)messageLength : 0u,
               connStr.c_str(), (unsigned)networkPortInstance, ok ? "" : " - FAILED (unknown/closed peer)");
        return ok ? messageLength : 0;
    }

    return 0;  // an instance neither port owns - not this router's to answer
}

}  // namespace CASSc
