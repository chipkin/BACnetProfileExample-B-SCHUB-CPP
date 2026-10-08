// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
#pragma once

// ScTransportRouter.h
// =============================================================================
// The stack <-> transport glue for this example (see sc_transport/README.md).
//
// WHY THIS EXISTS (and why it is not just two more functions in main.cpp).
// The CAS BACnet Stack holds exactly ONE function pointer for
// CallbackReceiveMessageForPort and ONE for CallbackSendMessageForPort.
// common/CASExampleHelper.cpp's own versions of those two callbacks are
// file-private and only know about UDP (BACnet/IP), and this example has no
// BACnet/IP port: its only data link is BACnet/SC. So it registers its OWN
// pair of callbacks - AFTER RegisterCommonCallbacks() has already supplied
// GetSystemTime, so that call ordering is still what wires GetSystemTime up -
// that move the stack's messages for the BACnet/SC Network Port (2) to and
// from ScTransport.
//
// This file never edits common/ - see the series' check-series.sh check 1
// (common/ byte-identical).
// =============================================================================

#include "ScTransport.h"

#include <cstdint>

namespace CASSc {

class ScTransportRouter {
public:
    // scNetworkPortInstance: the BACnet/SC Network Port object instance this
    // router answers the ...ForPort callbacks for (2 in this example - see
    // main.cpp). `transport` must outlive this router; DrainStatusEvents()
    // and the send/receive paths call it.
    ScTransportRouter(uint32_t scNetworkPortInstance, ScTransport& transport);
    ~ScTransportRouter();

    // Registers this router's ReceiveMessageForPort/SendMessageForPort
    // callbacks with the stack. MUST be called AFTER
    // CASExampleHelper::RegisterCommonCallbacks() - the stack only keeps the
    // LAST callback registered for each slot, and RegisterCommonCallbacks()
    // also supplies GetSystemTime (which this class does not re-register).
    void RegisterCallbacks();

    // Drains ScTransport's status-event queue and reports each one to the
    // stack via BACnetStack_SetBACnetSCWebSocketStatus. Call once per
    // main-loop tick, after ScTransport::Service(). A `false` return from
    // that stack call (peer not registered/already forgotten) is expected and
    // is not logged as an error.
    void DrainStatusEvents();

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
    uint32_t m_scNetworkPortInstance;
    ScTransport& m_transport;
};

}  // namespace CASSc
