// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
// SimpleUDP.cpp
// =============================================================================
// Cross-platform UDP socket wrapper - see SimpleUDP.h for the interface.
// =============================================================================

#include "SimpleUDP.h"

#include <string.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
// ws2_32 is linked by CMakeLists.txt. If you copy this file into a non-CMake
// MSVC project, add: #pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#define INVALID_SOCK INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#define INVALID_SOCK (-1)
#endif

namespace {
// One-time Winsock startup/teardown. No-op on POSIX.
struct PlatformInit {
    PlatformInit() {
#if defined(_WIN32)
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    }
    ~PlatformInit() {
#if defined(_WIN32)
        WSACleanup();
#endif
    }
};
PlatformInit g_platformInit;
} // namespace

SimpleUDP::SimpleUDP() : m_socket(INVALID_SOCK), m_connected(false) {}

SimpleUDP::~SimpleUDP() { Disconnect(); }

bool SimpleUDP::Connect(const uint16_t localPort) {
    m_socket = (intptr_t)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_socket == (intptr_t)INVALID_SOCK) {
        return false;
    }

    // Port-sharing policy. Read this before copying it into a product.
    //
    // BACnet/IP allows several devices to share UDP 47808 on one host, and that
    // is genuinely useful while developing (run two examples at once). But it has
    // a nasty failure mode: a STALE instance - or any other BACnet program - can
    // answer requests meant for your device, and a perfectly correct device then
    // looks broken. That is a classic day-one BACnet debugging trap.
    //
    // Windows and POSIX disagree about what SO_REUSEADDR means, so we do not use
    // the same option on both:
    //
    //   POSIX  - SO_REUSEADDR here mainly lets us rebind quickly after a restart
    //            (skipping TIME_WAIT). We keep it: restarting the example is the
    //            common case, and it is what makes multi-device testing possible.
    //   Windows- SO_REUSEADDR is far more permissive: it lets ANY other local
    //            process bind the same port and silently steal our traffic.
    //            Microsoft's guidance is SO_EXCLUSIVEADDRUSE, so that is what we
    //            ask for - we would rather fail loudly at bind() than be hijacked.
    //
    // If you are running two of these examples on one Windows host on purpose,
    // give one of them a different --port rather than relaxing this.
#if defined(_WIN32)
    const int exclusive = 1;
    setsockopt(m_socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               (const char*)&exclusive, sizeof(exclusive));
#else
    const int reuse = 1;
    setsockopt((int)m_socket, SOL_SOCKET, SO_REUSEADDR,
               (const char*)&reuse, sizeof(reuse));
#endif

    // Allow sending to the broadcast address (needed for I-Am replies, etc.).
    const int broadcast = 1;
    setsockopt((int)m_socket, SOL_SOCKET, SO_BROADCAST,
               (const char*)&broadcast, sizeof(broadcast));

    // No SO_RCVTIMEO. Receive() waits for a datagram with select() instead (see
    // the comment there): up to common/ 3.4.0 this set a 10 ms SO_RCVTIMEO and
    // Receive() called a blocking recvfrom(), and on Windows a datagram that
    // arrives just as that timed receive expires is silently discarded.

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(localPort);

    if (bind((int)m_socket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        Disconnect();
        return false;
    }

    m_connected = true;
    return true;
}

void SimpleUDP::Disconnect() {
    if (m_socket != (intptr_t)INVALID_SOCK) {
#if defined(_WIN32)
        closesocket((SOCKET)m_socket);
#else
        close((int)m_socket);
#endif
        m_socket = (intptr_t)INVALID_SOCK;
    }
    m_connected = false;
}

uint16_t SimpleUDP::Send(const uint8_t* ipAddress, const uint16_t port,
                         const uint8_t* data, const uint16_t length) {
    if (!m_connected || ipAddress == NULL || data == NULL) {
        return 0;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    memcpy(&dest.sin_addr.s_addr, ipAddress, 4); // IPv4 octets, network order

    int sent = sendto((int)m_socket, (const char*)data, (int)length, 0,
                      (struct sockaddr*)&dest, sizeof(dest));
    return (sent > 0) ? (uint16_t)sent : 0;
}

uint16_t SimpleUDP::Receive(uint8_t* buffer, const uint16_t maxLength,
                            uint8_t* fromIpAddress, uint16_t* fromPort) {
    if (!m_connected || buffer == NULL) {
        return 0;
    }

    // Wait up to RECEIVE_WAIT_MS for the socket to become readable, and call
    // recvfrom() only when it is. 10 ms keeps the device responsive (the tick
    // loop runs ~90x/sec when idle) while still yielding the CPU.
    //
    // Why select() and not SO_RCVTIMEO: up to common/ 3.4.0 the socket had a
    // 10 ms SO_RCVTIMEO and this called a blocking recvfrom() every tick. On
    // Windows, a datagram that arrives just as such a timed receive expires is
    // silently discarded - the next recvfrom() does not return it either. With
    // sparse traffic (a client sending one request every second or so) about 8%
    // of requests were lost on 127.0.0.1.
    // select() only reports readiness; the datagram stays queued until the
    // recvfrom() below, which then returns at once. select() is portable
    // (Winsock and POSIX), so both platforms use the same path.
    static const long RECEIVE_WAIT_MS = 10;
    fd_set readSet;
    FD_ZERO(&readSet);
#if defined(_WIN32)
    FD_SET((SOCKET)m_socket, &readSet);
    const int nfds = 0; // ignored by Winsock
#else
    FD_SET((int)m_socket, &readSet);
    const int nfds = (int)m_socket + 1;
#endif
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = RECEIVE_WAIT_MS * 1000;
    if (select(nfds, &readSet, NULL, NULL, &timeout) <= 0) {
        return 0; // timeout or error - nothing to process this tick
    }

    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    memset(&from, 0, sizeof(from));

    // The socket is readable, so this returns at once. On POSIX MSG_DONTWAIT
    // also guarantees it: Linux can report a UDP socket readable and then drop
    // the datagram (bad checksum), and a blocking recvfrom() would then wait for
    // the next one. Winsock has no MSG_DONTWAIT; there readability suffices.
#if defined(_WIN32)
    const int recvFlags = 0;
#else
    const int recvFlags = MSG_DONTWAIT;
#endif
    int received = recvfrom((int)m_socket, (char*)buffer, (int)maxLength, recvFlags,
                            (struct sockaddr*)&from, &fromLen);
    if (received <= 0) {
        return 0; // timeout or error - nothing to process this tick
    }

    if (fromIpAddress != NULL) {
        memcpy(fromIpAddress, &from.sin_addr.s_addr, 4);
    }
    if (fromPort != NULL) {
        *fromPort = ntohs(from.sin_port);
    }
    return (uint16_t)received;
}
