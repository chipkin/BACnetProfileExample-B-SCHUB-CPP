// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
#pragma once

// ScTransportRouter.h
// =============================================================================
// The stack <-> transport glue for this example, per
// docs/bacnet-sc-transport-plan.md's "ScTransportRouter" subsection.
//
// WHY THIS EXISTS (and why it is not just two more functions in main.cpp).
// The CAS BACnet Stack holds exactly ONE function pointer for
// CallbackReceiveMessageForPort and ONE for CallbackSendMessageForPort - not
// one per Network Port. common/CASExampleHelper.cpp's own versions of those
// two callbacks are file-private and only know about UDP (BACnet/IP), so this
// example cannot use CASExampleHelper::SetupUDP()/RegisterCommonCallbacks()
// for BOTH ports the way a single-transport example does: it must register
// its OWN pair of callbacks - AFTER RegisterCommonCallbacks() has already
// supplied GetSystemTime, so that call ordering is still what wires
// GetSystemTime up - that dispatch on networkPortInstance and handle Network
// Port 1 (BACnet/IP, via a SimpleUDP this class owns directly - NOT through
// SetupUDP) and Network Port 2 (BACnet/SC, via ScTransport) in one place.
//
// This file calls into common/'s PUBLIC classes (SimpleUDP) and functions
// (CASExampleHelper::GetLocalIPv4) but never edits common/ itself - see the
// series' check-series.sh check 1 (common/ byte-identical) and the plan's
// "Important constraints" section.
// =============================================================================

#include "ScTransport.h"
#include "SimpleUDP.h"

#include <cstdint>

namespace CASSc {

class ScTransportRouter {
public:
    // ipNetworkPortInstance/scNetworkPortInstance: the Network Port object
    // instances this router answers BACnetStack_Register...ForPort callbacks
    // for (1 and 2 in this example - see main.cpp). `transport` must outlive
    // this router; DrainStatusEvents() and the SC send/receive paths call it.
    ScTransportRouter(uint32_t ipNetworkPortInstance, uint32_t scNetworkPortInstance, ScTransport& transport);
    ~ScTransportRouter();

    // Binds this router's OWN UDP socket for the IP Network Port - the
    // BACnet/IP equivalent of CASExampleHelper::SetupUDP(), but owned here
    // instead, because HandleSendMessage/HandleReceiveMessage (below) must be
    // able to reach it directly (see the file header). Call once, before
    // RegisterCallbacks().
    bool Start(uint16_t udpPort);

    // Registers this router's ReceiveMessageForPort/SendMessageForPort
    // callbacks with the stack. MUST be called AFTER
    // CASExampleHelper::RegisterCommonCallbacks() - the stack only keeps the
    // LAST callback registered for each slot, and RegisterCommonCallbacks()
    // also supplies GetSystemTime (which this class does not re-register).
    void RegisterCallbacks();

    // Closes the router's UDP socket. Call once before the program exits.
    void Shutdown();

    // Drains ScTransport's status-event queue and reports each one to the
    // stack via BACnetStack_SetBACnetSCWebSocketStatus. Call once per
    // main-loop tick, after ScTransport::Service(). A `false` return from
    // that stack call (peer not registered/already forgotten) is expected and
    // is not logged as an error - see the plan's ScTransportRouter subsection.
    void DrainStatusEvents();

    // Broadcasts an unsolicited I-Am for `deviceInstance` on the IP Network
    // Port this router owns - the same local-subnet-broadcast computation as
    // CASExampleHelper::SendIAm, reimplemented here because that function only
    // knows about CASExampleHelper's OWN UDP bindings, not this router's.
    void SendIAm(uint32_t deviceInstance);

    // --- Callback bodies - public only so the free-function trampolines in
    // ScTransportRouter.cpp (the only things the stack can hold a pointer to)
    // can reach them. Not meant to be called by application code directly.
    uint16_t HandleReceiveMessage(uint8_t* message, uint16_t maxMessageLength,
                                   uint8_t* sourceConnectionString, uint8_t* sourceConnectionStringLength,
                                   uint8_t* destinationConnectionString, uint8_t* destinationConnectionStringLength,
                                   uint8_t maxConnectionStringLength, uint32_t* networkPortInstance);
    uint16_t HandleSendMessage(const uint8_t* message, uint16_t messageLength,
                               const uint8_t* connectionString, uint8_t connectionStringLength,
                               uint32_t networkPortInstance, bool broadcast);

private:
    uint16_t ReceiveFromIp(uint8_t* message, uint16_t maxMessageLength,
                            uint8_t* sourceConnectionString, uint8_t* sourceConnectionStringLength,
                            uint8_t maxConnectionStringLength, uint32_t* networkPortInstance);
    uint16_t ReceiveFromSc(uint8_t* message, uint16_t maxMessageLength,
                            uint8_t* sourceConnectionString, uint8_t* sourceConnectionStringLength,
                            uint8_t* destinationConnectionString, uint8_t* destinationConnectionStringLength,
                            uint8_t maxConnectionStringLength, uint32_t* networkPortInstance);

    uint32_t m_ipNetworkPortInstance;
    uint32_t m_scNetworkPortInstance;
    ScTransport& m_transport;

    SimpleUDP m_udp;
    uint16_t m_udpPort = 0;
    bool m_udpBound = false;

    // Alternates which transport is polled first on each call to
    // HandleReceiveMessage, so neither one can starve the other (plan:
    // "alternate IP-first/SC-first each Tick").
    bool m_pollIpFirst = true;
};

}  // namespace CASSc
