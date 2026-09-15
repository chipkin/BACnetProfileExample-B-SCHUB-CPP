// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
#ifndef SIMPLE_UDP_H
#define SIMPLE_UDP_H

// SimpleUDP.h
// =============================================================================
// A minimal, cross-platform UDP socket wrapper used by the BACnet example
// projects. It is intentionally small: just enough to bind a port, send a
// datagram to an IPv4 address, and receive one (non-blocking with a short
// timeout). On Windows it uses Winsock2 (link ws2_32); on Linux/macOS it uses
// BSD sockets.
//
// This is plain, unrestricted example code - copy it into your own project.
// =============================================================================

#include <stdint.h>
#include <stddef.h>

class SimpleUDP {
public:
    SimpleUDP();
    ~SimpleUDP();

    // Bind the UDP socket to localPort (BACnet/IP default is 47808 / 0xBAC0).
    // Enables address reuse and broadcast. Returns true on success.
    bool Connect(uint16_t const localPort);

    // Close the socket.
    void Disconnect();

    // Send 'length' bytes to ipAddress[4] (4 octets) : port.
    // Returns the number of bytes sent, or 0 on failure.
    // (Named Send, not SendMessage, to avoid the Win32 <windows.h> macro that
    //  #defines SendMessage to SendMessageA.)
    uint16_t Send(const uint8_t* ipAddress, const uint16_t port,
                  const uint8_t* data, const uint16_t length);

    // Try to receive one datagram into buffer (up to maxLength bytes).
    // Non-blocking-ish: waits up to the socket receive timeout. Returns the
    // number of bytes received (0 if none / timeout). On success, fills
    // fromIpAddress[4] and *fromPort with the sender's address.
    // (Named Receive, not GetMessage, to avoid the Win32 GetMessage macro.)
    uint16_t Receive(uint8_t* buffer, const uint16_t maxLength,
                     uint8_t* fromIpAddress, uint16_t* fromPort);

private:
    // Stored as an int to avoid leaking platform socket headers here.
    // (SOCKET on Windows, file descriptor on POSIX.)
    intptr_t m_socket;
    bool m_connected;
};

#endif // SIMPLE_UDP_H
