// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
// CASExampleHelper.cpp
// =============================================================================
// Implementation of the shared example boilerplate. See CASExampleHelper.h.
// =============================================================================

#include "CASExampleHelper.h"
#include "SimpleUDP.h"
#include "CASBACnetStackExampleConstants.h"

// The CAS BACnet Stack C API, via the adapter: BACnetStack_* is called directly here,
// the same call in every link mode (source/static/DLL) - see CASBACnetStackAdapter.h.
// The caller's main() must have already called LoadBACnetFunctions() successfully.
#include "CASBACnetStackAdapter.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#if defined(_WIN32)
#include <conio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
// ws2_32 + iphlpapi are linked by CMakeLists.txt. If you copy this file into a
// non-CMake MSVC project, add:
//   #pragma comment(lib, "ws2_32.lib")
//   #pragma comment(lib, "iphlpapi.lib")
#else
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

namespace {

// ---------------------------------------------------------------------------
// Multi-port UDP support (common/ 2.3.0).
//
// The stack calls the transport callbacks as plain C function pointers (no
// user-data argument), so the socket(s) live here as file-local state rather
// than being passed in. Originally that state was exactly one SimpleUDP - one
// example, one BACnet/IP link. A routing example (B-RTR, the first canonical
// user of this) owns TWO Network Port objects, each with its own UDP socket
// and port number, and the stack must be told - on every receive and every
// send - WHICH Network Port instance the datagram belongs to. This small
// table generalizes "the one socket" to "up to MAX_UDP_BINDINGS sockets, each
// keyed by the Network Port instance it belongs to".
//
// WHY THIS IS SAFE FOR SINGLE-PORT EXAMPLES.
// Every example that only ever calls the single-argument SetupUDP(port) gets
// exactly one entry in g_udpBindings, keyed to whatever SetNetworkPortInstance
// set (instance 1 if it was never called - unchanged default). With one
// entry, HelperReceiveMessage's round-robin loop below always starts at and
// checks that one entry (nothing to rotate to), and HelperSendMessage's
// lookup always finds that one entry for the one networkPortInstance the
// stack will ever name. The code path is byte-for-byte the same work the
// old single-g_udp implementation did; only the storage changed from "a bare
// SimpleUDP" to "a SimpleUDP inside a one-element table". No single-port
// example's on-the-wire behaviour changes.
struct UdpBinding {
    SimpleUDP udp;
    uint16_t port = 0;
    uint32_t networkPortInstance = 0;
    bool bound = false;
};

// Generous headroom over B-RTR's two ports; a small fixed table avoids a heap
// allocation in example code that otherwise has none.
const size_t MAX_UDP_BINDINGS = 4;
UdpBinding g_udpBindings[MAX_UDP_BINDINGS];
size_t g_udpBindingCount = 0;

UdpBinding* FindUdpBindingByInstance(uint32_t networkPortInstance) {
    for (size_t i = 0; i < g_udpBindingCount; ++i) {
        if (g_udpBindings[i].networkPortInstance == networkPortInstance) {
            return &g_udpBindings[i];
        }
    }
    return NULL;
}

// The BACnet/IP port of the CURRENT Network Port instance (used to address
// broadcast I-Am for the single-argument SendIAm()).
uint16_t g_port = 47808;

// The instance of the Network Port object that the single-argument
// SetupUDP(port) / SendIAm(deviceInstance) overloads act on. The stack
// identifies a link by its Network Port object INSTANCE, not by a transport
// network type, so the transport callbacks and SendIAm all have to name it.
// The example's main() tells us which one is "current" via
// SetNetworkPortInstance(); the default matches the series convention of a
// single Network Port at instance 1.
uint32_t g_networkPortInstance = 1;

// ---------------------------------------------------------------------------
// Transport callback: the stack calls this to RECEIVE a BACnet message.
//
// We pull one datagram off the UDP socket. If one arrived, we copy it into the
// stack's message buffer and report who it came from via the "connection
// string" - for BACnet/IP that is 6 bytes: 4 IP octets + 2 port bytes
// (big-endian). Returning 0 means "nothing to process this tick".
// ---------------------------------------------------------------------------
uint16_t HelperReceiveMessage(uint8_t* message, const uint16_t maxMessageLength,
                              uint8_t* sourceConnectionString,
                              uint8_t* sourceConnectionStringLength,
                              uint8_t* destinationConnectionString,
                              uint8_t* destinationConnectionStringLength,
                              const uint8_t maxConnectionStringLength,
                              uint32_t* networkPortInstance) {
    (void)destinationConnectionString;
    (void)destinationConnectionStringLength;
    if (maxConnectionStringLength < 6 || g_udpBindingCount == 0) {
        return 0;
    }

    // Poll the bound sockets in round-robin order, starting from the one after
    // whichever was serviced (or checked) last call. For a single-port example
    // (g_udpBindingCount == 1) this always checks binding 0, same as the old
    // single-g_udp implementation. For a multi-port example it means a socket
    // with continuous traffic cannot starve the others: each call to this
    // function looks at a different starting socket, and the stack calls it
    // repeatedly per tick until it returns 0.
    static size_t s_nextBindingToCheck = 0;
    const size_t n = g_udpBindingCount;
    uint16_t bytesRead = 0;
    uint8_t fromIp[4] = { 0, 0, 0, 0 };
    uint16_t fromPort = 0;
    uint32_t servicedInstance = 0;

    for (size_t k = 0; k < n; ++k) {
        const size_t i = (s_nextBindingToCheck + k) % n;
        UdpBinding& binding = g_udpBindings[i];
        if (!binding.bound) {
            continue;
        }
        // Receive() copies at most maxMessageLength bytes; a datagram larger than
        // the stack's buffer is truncated to that length (fine for UDP - the
        // stack will simply fail to decode and ignore an over-length frame).
        bytesRead = binding.udp.Receive(message, maxMessageLength, fromIp, &fromPort);
        if (bytesRead > 0) {
            servicedInstance = binding.networkPortInstance;
            s_nextBindingToCheck = (i + 1) % n;
            break;
        }
    }
    if (bytesRead == 0) {
        s_nextBindingToCheck = (s_nextBindingToCheck + 1) % n; // keep rotating even when idle
        return 0; // no datagram waiting on any bound port
    }

    printf("RX %u bytes from %u.%u.%u.%u:%u (Network Port %u)", (unsigned)bytesRead,
           fromIp[0], fromIp[1], fromIp[2], fromIp[3], (unsigned)fromPort,
           (unsigned)servicedInstance);
    CASExampleHelper::LogBacnetFrame(message, bytesRead);

    // Fill the 6-byte BACnet/IP connection string: IP[4] + port[2] (big-endian).
    sourceConnectionString[0] = fromIp[0];
    sourceConnectionString[1] = fromIp[1];
    sourceConnectionString[2] = fromIp[2];
    sourceConnectionString[3] = fromIp[3];
    sourceConnectionString[4] = (uint8_t)((fromPort >> 8) & 0xFF);
    sourceConnectionString[5] = (uint8_t)(fromPort & 0xFF);
    *sourceConnectionStringLength = 6;

    // Tell the stack WHICH Network Port object this datagram arrived on. The
    // stack used to ask only for the transport's network TYPE here; since the
    // per-port work (CAS BACnet Stack issue #822/#556) it wants the instance of
    // the Network Port object that owns this link, so a multi-port device can
    // answer on the port a request came in on. A single-port example reports
    // its one bound instance every time, same as before common/ 2.3.0; a
    // multi-port example reports whichever bound socket the datagram actually
    // arrived on.
    *networkPortInstance = servicedInstance;
    return bytesRead;
}

// ---------------------------------------------------------------------------
// Transport callback: the stack calls this to SEND a BACnet message.
//
// The stack hands us the destination as a connection string (IP[4] + port[2]).
// For broadcasts the stack fills it with the broadcast address, so we can send
// the same way in both cases (the socket has SO_BROADCAST enabled).
// ---------------------------------------------------------------------------
uint16_t HelperSendMessage(const uint8_t* message, const uint16_t messageLength,
                           const uint8_t* connectionString,
                           const uint8_t connectionStringLength,
                           const uint32_t networkPortInstance, const bool broadcast) {
    // The stack names the Network Port object the message is to leave by (it
    // used to name the transport's network type). Look up the socket bound to
    // that instance; a single-port example has exactly one, so this always
    // resolves to it - same effect as the old "!= g_networkPortInstance" check,
    // just expressed as a table lookup instead of a single comparison.
    UdpBinding* binding = FindUdpBindingByInstance(networkPortInstance);
    if (binding == NULL || !binding->bound || connectionStringLength < 6) {
        return 0;
    }

    const uint8_t ip[4] = { connectionString[0], connectionString[1],
                            connectionString[2], connectionString[3] };
    const uint16_t port = (uint16_t)((connectionString[4] << 8) | connectionString[5]);

    const uint16_t sent = binding->udp.Send(ip, port, message, messageLength);
    printf("TX %u bytes to %u.%u.%u.%u:%u%s (Network Port %u)", (unsigned)sent,
           ip[0], ip[1], ip[2], ip[3], (unsigned)port,
           broadcast ? " (broadcast)" : "", (unsigned)networkPortInstance);
    CASExampleHelper::LogBacnetFrame(message, messageLength);
    return sent;
}

// ---------------------------------------------------------------------------
// Time callback: the stack asks the application for the current system time.
// ---------------------------------------------------------------------------
// CASBACnetTime is the stack's own time type (int64_t seconds since the UNIX
// epoch). It replaced time_t, whose width differs between platforms and build
// settings - a 32-bit time_t on one side of the ABI and a 64-bit one on the
// other silently corrupted every timestamp.
CASBACnetTime HelperGetSystemTime() {
    return (CASBACnetTime)time(0);
}

// ---------------------------------------------------------------------------
// Find the primary network interface's negotiated link speed, in bits per
// second (what the Network Port object's Link_Speed property reports - a
// REAL, 0.0 meaning "indeterminable" per Clause 12.56.15). Same interface
// selection as GetPrimaryIPv4 (first non-loopback, "up" IPv4 interface) -
// deliberately not shared code with it: Windows needs a second API call
// (GetIfEntry) keyed off the adapter's index, and POSIX needs the interface
// NAME rather than its address, so the loop bodies diverge enough that
// factoring out "the one interface" isn't worth it for two ~30-line
// functions called once each, at start-up. Returns false (leaves
// *bitsPerSecond untouched) if no interface was found or its speed could not
// be read - the caller then reports 0.0 ("indeterminable"), which is honest,
// not this function silently inventing a number.
bool GetPrimaryLinkSpeedBitsPerSecond(double* bitsPerSecond) {
#if defined(_WIN32)
    IP_ADAPTER_INFO adapters[32];
    ULONG len = sizeof(adapters);
    if (GetAdaptersInfo(adapters, &len) != ERROR_SUCCESS) {
        return false;
    }
    for (const IP_ADAPTER_INFO* a = adapters; a != NULL; a = a->Next) {
        struct in_addr ipAddr;
        if (inet_pton(AF_INET, a->IpAddressList.IpAddress.String, &ipAddr) != 1) {
            continue;
        }
        const uint32_t ipN = ipAddr.s_addr;
        if (ipN == 0 || (ipN & 0xFF) == 127) {
            continue; // no address, or loopback - same exclusions as GetPrimaryIPv4
        }
        MIB_IFROW ifRow;
        memset(&ifRow, 0, sizeof(ifRow));
        ifRow.dwIndex = a->Index;
        if (GetIfEntry(&ifRow) != NO_ERROR) {
            return false;
        }
        *bitsPerSecond = (double)ifRow.dwSpeed; // already bits/sec on this API
        return true;
    }
    return false;
#else
    struct ifaddrs* ifap = NULL;
    if (getifaddrs(&ifap) != 0) {
        return false;
    }
    bool found = false;
    for (const struct ifaddrs* ifa = ifap; ifa != NULL && !found; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if ((ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP)) {
            continue;
        }
        // /sys/class/net/<iface>/speed - the kernel's own view of the negotiated
        // link speed in Mbit/s (an ethtool query would need root on some distros
        // and a <linux/ethtool.h> dependency this file doesn't otherwise have;
        // the sysfs file is the same number, readable by anyone, no extra headers).
        // Reads "-1" (or fails to open) for a link that's down or doesn't expose
        // a speed (e.g. some virtual/tunnel interfaces) - either way, no value.
        char path[64];
        snprintf(path, sizeof(path), "/sys/class/net/%s/speed", ifa->ifa_name);
        FILE* f = fopen(path, "r");
        if (f == NULL) {
            continue;
        }
        long mbps = -1;
        const int scanned = fscanf(f, "%ld", &mbps);
        fclose(f);
        if (scanned == 1 && mbps > 0) {
            *bitsPerSecond = (double)mbps * 1000000.0;
            found = true;
        }
    }
    freeifaddrs(ifap);
    return found;
#endif
}

// ---------------------------------------------------------------------------
// Find the primary IPv4 interface's address and subnet mask (each 4 octets in
// network/big-endian order, i.e. ip[0] is the first dotted octet). These feed
// the Network Port object (IP_Address, IP_Subnet_Mask) and the local broadcast.
// Returns true and fills ip[4]/mask[4] on success.
// ---------------------------------------------------------------------------
bool GetPrimaryIPv4(uint8_t ip[4], uint8_t mask[4]) {
#if defined(_WIN32)
    IP_ADAPTER_INFO adapters[32];
    ULONG len = sizeof(adapters);
    if (GetAdaptersInfo(adapters, &len) != ERROR_SUCCESS) {
        return false;
    }
    for (const IP_ADAPTER_INFO* a = adapters; a != NULL; a = a->Next) {
        struct in_addr ipAddr;
        struct in_addr maskAddr;
        maskAddr.s_addr = 0; // default if the mask string fails to parse (below)
        if (inet_pton(AF_INET, a->IpAddressList.IpAddress.String, &ipAddr) != 1) {
            continue;            // not a valid IPv4 address
        }
        // The subnet mask is best-effort: if it does not parse, leave it 0.0.0.0,
        // which makes the local broadcast fall back to 255.255.255.255 (the limited
        // broadcast) - the same behaviour as the POSIX path with no netmask. Always
        // check the return; never read an uninitialised in_addr.
        if (inet_pton(AF_INET, a->IpAddressList.IpMask.String, &maskAddr) != 1) {
            maskAddr.s_addr = 0;
        }
        const uint32_t ipN = ipAddr.s_addr;   // network byte order
        const uint32_t maskN = maskAddr.s_addr;
        if (ipN == 0) {
            continue;            // interface has no address (0.0.0.0)
        }
        if ((ipN & 0xFF) == 127) {
            continue;            // skip loopback (127.x.x.x)
        }
        memcpy(ip, &ipN, 4);
        memcpy(mask, &maskN, 4);
        return true;
    }
    return false;
#else
    struct ifaddrs* ifap = NULL;
    if (getifaddrs(&ifap) != 0) {
        return false;
    }
    bool found = false;
    for (const struct ifaddrs* ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if ((ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP)) {
            continue;
        }
        const uint32_t ipN = ((const struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
        const uint32_t maskN = ifa->ifa_netmask
            ? ((const struct sockaddr_in*)ifa->ifa_netmask)->sin_addr.s_addr : 0;
        memcpy(ip, &ipN, 4);
        memcpy(mask, &maskN, 4);
        found = true;
        break;
    }
    freeifaddrs(ifap);
    return found;
#endif
}

#if !defined(_WIN32)
// POSIX terminal raw-mode handling for non-blocking single-key reads.
struct termios g_origTermios;
bool g_rawActive = false;      // true only if we put a REAL tty into raw mode
bool g_stdinConfigured = false; // true once we have tried, tty or not

void EnableRawInput() {
    if (g_stdinConfigured) {
        return;
    }
    g_stdinConfigured = true;

    // Set O_NONBLOCK FIRST, and UNCONDITIONALLY - before the tty check.
    //
    // This ordering is load-bearing. PollKey() read()s stdin on every tick of the
    // main loop. If stdin is NOT a tty (CI, `docker run -i` without -t, a pipe
    // with no data yet) and O_NONBLOCK was never set, that read() BLOCKS FOREVER:
    // BACnetStack_Tick() never runs again and the device goes deaf while still
    // looking perfectly alive. Redirecting `< /dev/null` hides it, because EOF
    // returns 0 immediately - which is why it survives most smoke tests.
    const int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (flags != -1) {
        fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    }

    // Raw mode only means anything for a real terminal. Not having one is fine -
    // we simply do not get single-key input, and the non-blocking read above
    // keeps the tick loop healthy either way.
    if (tcgetattr(STDIN_FILENO, &g_origTermios) != 0) {
        return; // not a tty (e.g. piped or no terminal) - leave termios alone
    }
    struct termios raw = g_origTermios;
    raw.c_lflag &= ~(unsigned)(ICANON | ECHO); // no line buffering, no echo
    raw.c_cc[VMIN] = 0;                          // non-blocking read
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    g_rawActive = true; // only now do we own the terminal state
}
#endif

// ---------------------------------------------------------------------------
// Deferred-restart state (see the DM-RD-B block in CASExampleHelper.h).
//
// The clock here must be MONOTONIC, not wall-clock: a device that supports
// TimeSynchronization (DM-TS-B) can have its wall clock stepped - possibly
// backwards - by a management station at any moment, including during the
// restart delay. time() would then either fire the restart early or park it in
// the future indefinitely. A monotonic source cannot be stepped.
// ---------------------------------------------------------------------------
bool g_restartPending = false;
uint64_t g_restartDueAtMs = 0;
CASExampleHelper::RestartKind g_restartKind = CASExampleHelper::RestartKind::Warm;

uint64_t MonotonicMilliseconds() {
#if defined(_WIN32)
    // GetTickCount64 (not GetTickCount): the 32-bit version wraps to zero after
    // ~49.7 days of uptime, which would make a pending deadline unreachable.
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

} // namespace

namespace {

// ANSI/ASHRAE 135 Clause 21 confirmed-service-choice names, index = the wire
// value. Includes the two removed-but-still-numbered choices (13, 24, 25) so
// an old/malformed frame using them still gets a name instead of falling
// through to the numeric fallback.
const char* ConfirmedServiceName(uint8_t choice) {
    static const char* const names[] = {
        "AcknowledgeAlarm", "ConfirmedCOVNotification", "ConfirmedEventNotification",
        "GetAlarmSummary", "GetEnrollmentSummary", "SubscribeCOV", "AtomicReadFile",
        "AtomicWriteFile", "AddListElement", "RemoveListElement", "CreateObject",
        "DeleteObject", "ReadProperty", "ReadPropertyConditional", "ReadPropertyMultiple",
        "WriteProperty", "WritePropertyMultiple", "DeviceCommunicationControl",
        "ConfirmedPrivateTransfer", "ConfirmedTextMessage", "ReinitializeDevice",
        "VTOpen", "VTClose", "VTData", "Authenticate", "RequestKey", "ReadRange",
        "LifeSafetyOperation", "SubscribeCOVProperty", "GetEventInformation",
        "SubscribeCOVPropertyMultiple", "ConfirmedCOVNotificationMultiple"
    };
    if (choice < sizeof(names) / sizeof(names[0])) {
        return names[choice];
    }
    return NULL;
}

// Clause 21 unconfirmed-service-choice names.
const char* UnconfirmedServiceName(uint8_t choice) {
    static const char* const names[] = {
        "I-Am", "I-Have", "UnconfirmedCOVNotification", "UnconfirmedEventNotification",
        "UnconfirmedPrivateTransfer", "UnconfirmedTextMessage", "TimeSynchronization",
        "Who-Has", "Who-Is", "UTCTimeSynchronization", "WriteGroup",
        "UnconfirmedCOVNotificationMultiple"
    };
    if (choice < sizeof(names) / sizeof(names[0])) {
        return names[choice];
    }
    return NULL;
}

const char* RejectReasonName(uint8_t reason) {
    static const char* const names[] = {
        "other", "buffer-overflow", "inconsistent-parameters",
        "invalid-parameter-data-type", "invalid-tag", "missing-required-parameter",
        "parameter-out-of-range", "too-many-arguments", "undefined-enumeration",
        "unrecognized-service"
    };
    if (reason < sizeof(names) / sizeof(names[0])) {
        return names[reason];
    }
    return NULL;
}

const char* AbortReasonName(uint8_t reason) {
    static const char* const names[] = {
        "other", "buffer-overflow", "invalid-apdu-in-this-state",
        "preempted-by-higher-priority-task", "segmentation-not-supported",
        "security-error", "insufficient-security", "window-size-out-of-range",
        "application-exceeded-reply-time", "out-of-resources", "tsm-timeout",
        "apdu-too-long"
    };
    if (reason < sizeof(names) / sizeof(names[0])) {
        return names[reason];
    }
    return NULL;
}

// Only the handful actually seen in this series' examples (routing discovery
// and network-number discovery); everything else falls back to "type=<N>".
const char* NetworkMessageName(uint8_t type) {
    switch (type) {
        case 0: return "Who-Is-Router-To-Network";
        case 1: return "I-Am-Router-To-Network";
        case 2: return "I-Could-Be-Router-To-Network";
        case 3: return "Reject-Message-To-Network";
        case 4: return "Router-Busy-To-Network";
        case 5: return "Router-Available-To-Network";
        case 6: return "Initialize-Routing-Table";
        case 7: return "Initialize-Routing-Table-Ack";
        case 18: return "What-Is-Network-Number";
        case 19: return "Network-Number-Is";
        default: return NULL;
    }
}

// --- Object type / property identifier name tables --------------------------
// Generated from the pinned stack's own BACnetObjectType.h /
// BACnetPropertyIdentifier.h (the authoritative source for names AND values -
// see common/CHANGELOG.md 2.7.0 for the exact generation script; do not
// hand-edit individual rows, regenerate both tables together if the stack
// pin changes). Sorted ascending by id - LookUpIdName binary-searches this,
// so a hand-edit that breaks the ordering breaks every lookup after it
// silently (no runtime check).
struct IdName {
    uint32_t id;
    const char* name;
};

const IdName OBJECT_TYPE_NAMES[] = {
    { 0, "Analog_Input" },
    { 1, "Analog_Output" },
    { 2, "Analog_Value" },
    { 3, "Binary_Input" },
    { 4, "Binary_Output" },
    { 5, "Binary_Value" },
    { 6, "Calendar" },
    { 7, "Command" },
    { 8, "Device" },
    { 9, "Event_Enrollment" },
    { 10, "File" },
    { 11, "Group" },
    { 12, "Loop" },
    { 13, "Multi_State_Input" },
    { 14, "Multi_State_Output" },
    { 15, "Notification_Class" },
    { 16, "Program" },
    { 17, "Schedule" },
    { 18, "Averaging" },
    { 19, "Multi_State_Value" },
    { 20, "Trend_Log" },
    { 21, "Life_Safety_Point" },
    { 22, "Life_Safety_Zone" },
    { 23, "Accumulator" },
    { 24, "Pulse_Converter" },
    { 25, "Event_Log" },
    { 26, "Global_Group" },
    { 27, "Trend_Log_Multiple" },
    { 28, "Load_Control" },
    { 29, "Structured_View" },
    { 30, "Access_Door" },
    { 31, "Timer" },
    { 32, "Access_Credential" },
    { 33, "Access_Point" },
    { 34, "Access_Rights" },
    { 35, "Access_User" },
    { 36, "Access_Zone" },
    { 37, "Credential_Data_Input" },
    { 38, "Network_Security" },
    { 39, "Bitstring_Value" },
    { 40, "Characterstring_Value" },
    { 41, "Datepattern_Value" },
    { 42, "Date_Value" },
    { 43, "Datetimepattern_Value" },
    { 44, "Datetime_Value" },
    { 45, "Integer_Value" },
    { 46, "Large_Analog_Value" },
    { 47, "Octetstring_Value" },
    { 48, "Positive_Integer_Value" },
    { 49, "Timepattern_Value" },
    { 50, "Time_Value" },
    { 51, "Notification_Forwarder" },
    { 52, "Alert_Enrollment" },
    { 53, "Channel" },
    { 54, "Lighting_Output" },
    { 55, "Binary_Lighting_Output" },
    { 56, "Network_Port" },
    { 57, "Elevator_Group" },
    { 58, "Escalator" },
    { 59, "Lift" },
    { 60, "Staging" },
    { 61, "Audit_Log" },
    { 62, "Audit_Reporter" },
    { 63, "Color" },
    { 64, "Color_Temperature" },
};

const IdName PROPERTY_NAMES[] = {
    { 0, "Acked_Transitions" },
    { 1, "Ack_Required" },
    { 2, "Action" },
    { 3, "Action_Text" },
    { 4, "Active_Text" },
    { 5, "Active_Vt_Sessions" },
    { 6, "Alarm_Value" },
    { 7, "Alarm_Values" },
    { 8, "All" },
    { 9, "All_Writes_Successful" },
    { 10, "Apdu_Segment_Timeout" },
    { 11, "Apdu_Timeout" },
    { 12, "Application_Software_Version" },
    { 13, "Archive" },
    { 14, "Bias" },
    { 15, "Change_Of_State_Count" },
    { 16, "Change_Of_State_Time" },
    { 17, "Notification_Class" },
    { 19, "Controlled_Variable_Reference" },
    { 20, "Controlled_Variable_Units" },
    { 21, "Controlled_Variable_Value" },
    { 22, "Cov_Increment" },
    { 23, "Date_List" },
    { 24, "Daylight_Savings_Status" },
    { 25, "Deadband" },
    { 26, "Derivative_Constant" },
    { 27, "Derivative_Constant_Units" },
    { 28, "Description" },
    { 29, "Description_Of_Halt" },
    { 30, "Device_Address_Binding" },
    { 31, "Device_Type" },
    { 32, "Effective_Period" },
    { 33, "Elapsed_Active_Time" },
    { 34, "Error_Limit" },
    { 35, "Event_Enable" },
    { 36, "Event_State" },
    { 37, "Event_Type" },
    { 38, "Exception_Schedule" },
    { 39, "Fault_Values" },
    { 40, "Feedback_Value" },
    { 41, "File_Access_Method" },
    { 42, "File_Size" },
    { 43, "File_Type" },
    { 44, "Firmware_Revision" },
    { 45, "High_Limit" },
    { 46, "Inactive_Text" },
    { 47, "In_Process" },
    { 48, "Instance_Of" },
    { 49, "Integral_Constant" },
    { 50, "Integral_Constant_Units" },
    { 51, "Issue_Confirmed_Notifications" },
    { 52, "Limit_Enable" },
    { 53, "List_Of_Group_Members" },
    { 54, "List_Of_Object_Property_References" },
    { 56, "Local_Date" },
    { 57, "Local_Time" },
    { 58, "Location" },
    { 59, "Low_Limit" },
    { 60, "Manipulated_Variable_Reference" },
    { 61, "Maximum_Output" },
    { 62, "Max_Apdu_Length_Accepted" },
    { 63, "Max_Info_Frames" },
    { 64, "Max_Manager" },
    { 65, "Max_Pres_Value" },
    { 66, "Minimum_Off_Time" },
    { 67, "Minimum_On_Time" },
    { 68, "Minimum_Output" },
    { 69, "Min_Pres_Value" },
    { 70, "Model_Name" },
    { 71, "Modification_Date" },
    { 72, "Notify_Type" },
    { 73, "Number_Of_Apdu_Retries" },
    { 74, "Number_Of_States" },
    { 75, "Object_Identifier" },
    { 76, "Object_List" },
    { 77, "Object_Name" },
    { 78, "Object_Property_Reference" },
    { 79, "Object_Type" },
    { 80, "Optional" },
    { 81, "Out_Of_Service" },
    { 82, "Output_Units" },
    { 83, "Event_Parameters" },
    { 84, "Polarity" },
    { 85, "Present_Value" },
    { 86, "Priority" },
    { 87, "Priority_Array" },
    { 88, "Priority_For_Writing" },
    { 89, "Process_Identifier" },
    { 90, "Program_Change" },
    { 91, "Program_Location" },
    { 92, "Program_State" },
    { 93, "Proportional_Constant" },
    { 94, "Proportional_Constant_Units" },
    { 96, "Protocol_Object_Types_Supported" },
    { 97, "Protocol_Services_Supported" },
    { 98, "Protocol_Version" },
    { 99, "Read_Only" },
    { 100, "Reason_For_Halt" },
    { 102, "Recipient_List" },
    { 103, "Reliability" },
    { 104, "Relinquish_Default" },
    { 105, "Required" },
    { 106, "Resolution" },
    { 107, "Segmentation_Supported" },
    { 108, "Setpoint" },
    { 109, "Setpoint_Reference" },
    { 110, "State_Text" },
    { 111, "Status_Flags" },
    { 112, "System_Status" },
    { 113, "Time_Delay" },
    { 114, "Time_Of_Active_Time_Reset" },
    { 115, "Time_Of_State_Count_Reset" },
    { 116, "Time_Synchronization_Recipients" },
    { 117, "Units" },
    { 118, "Update_Interval" },
    { 119, "Utc_Offset" },
    { 120, "Vendor_Identifier" },
    { 121, "Vendor_Name" },
    { 122, "Vt_Classes_Supported" },
    { 123, "Weekly_Schedule" },
    { 124, "Attempted_Samples" },
    { 125, "Average_Value" },
    { 126, "Buffer_Size" },
    { 127, "Client_Cov_Increment" },
    { 128, "Cov_Resubscription_Interval" },
    { 130, "Event_Time_Stamps" },
    { 131, "Log_Buffer" },
    { 132, "Log_Device_Object_Property" },
    { 133, "Enable" },
    { 134, "Log_Interval" },
    { 135, "Maximum_Value" },
    { 136, "Minimum_Value" },
    { 137, "Notification_Threshold" },
    { 139, "Protocol_Revision" },
    { 140, "Records_Since_Notification" },
    { 141, "Record_Count" },
    { 142, "Start_Time" },
    { 143, "Stop_Time" },
    { 144, "Stop_When_Full" },
    { 145, "Total_Record_Count" },
    { 146, "Valid_Samples" },
    { 147, "Window_Interval" },
    { 148, "Window_Samples" },
    { 149, "Maximum_Value_Timestamp" },
    { 150, "Minimum_Value_Timestamp" },
    { 151, "Variance_Value" },
    { 152, "Active_Cov_Subscriptions" },
    { 153, "Backup_Failure_Timeout" },
    { 154, "Configuration_Files" },
    { 155, "Database_Revision" },
    { 156, "Direct_Reading" },
    { 157, "Last_Restore_Time" },
    { 158, "Maintenance_Required" },
    { 159, "Member_Of" },
    { 160, "Mode" },
    { 161, "Operation_Expected" },
    { 162, "Setting" },
    { 163, "Silenced" },
    { 164, "Tracking_Value" },
    { 165, "Zone_Members" },
    { 166, "Life_Safety_Alarm_Values" },
    { 167, "Max_Segments_Accepted" },
    { 168, "Profile_Name" },
    { 169, "Auto_Subordinate_Discovery" },
    { 170, "Manual_Subordinate_Address_Binding" },
    { 171, "Subordinate_Address_Binding" },
    { 172, "Subordinate_Proxy_Enable" },
    { 173, "Last_Notify_Record" },
    { 174, "Schedule_Default" },
    { 175, "Accepted_Modes" },
    { 176, "Adjust_Value" },
    { 177, "Count" },
    { 178, "Count_Before_Change" },
    { 179, "Count_Change_Time" },
    { 180, "Cov_Period" },
    { 181, "Input_Reference" },
    { 182, "Limit_Monitoring_Interval" },
    { 183, "Logging_Object" },
    { 184, "Logging_Record" },
    { 185, "Prescale" },
    { 186, "Pulse_Rate" },
    { 187, "Scale" },
    { 188, "Scale_Factor" },
    { 189, "Update_Time" },
    { 190, "Value_Before_Change" },
    { 191, "Value_Set" },
    { 192, "Value_Change_Time" },
    { 193, "Align_Intervals" },
    { 195, "Interval_Offset" },
    { 196, "Last_Restart_Reason" },
    { 197, "Logging_Type" },
    { 202, "Restart_Notification_Recipients" },
    { 203, "Time_Of_Device_Restart" },
    { 204, "Time_Synchronization_Interval" },
    { 205, "Trigger" },
    { 206, "Utc_Time_Synchronization_Recipients" },
    { 207, "Node_Subtype" },
    { 208, "Node_Type" },
    { 209, "Structured_Object_List" },
    { 210, "Subordinate_Annotations" },
    { 211, "Subordinate_List" },
    { 212, "Actual_Shed_Level" },
    { 213, "Duty_Window" },
    { 214, "Expected_Shed_Level" },
    { 215, "Full_Duty_Baseline" },
    { 218, "Requested_Shed_Level" },
    { 219, "Shed_Duration" },
    { 220, "Shed_Level_Descriptions" },
    { 221, "Shed_Levels" },
    { 222, "State_Description" },
    { 226, "Door_Alarm_State" },
    { 227, "Door_Extended_Pulse_Time" },
    { 228, "Door_Members" },
    { 229, "Door_Open_Too_Long_Time" },
    { 230, "Door_Pulse_Time" },
    { 231, "Door_Status" },
    { 232, "Door_Unlock_Delay_Time" },
    { 233, "Lock_Status" },
    { 234, "Masked_Alarm_Values" },
    { 235, "Secured_Status" },
    { 244, "Absentee_Limit" },
    { 245, "Access_Alarm_Events" },
    { 246, "Access_Doors" },
    { 247, "Access_Event" },
    { 248, "Access_Event_Authentication_Factor" },
    { 249, "Access_Event_Credential" },
    { 250, "Access_Event_Time" },
    { 251, "Access_Transaction_Events" },
    { 252, "Accompaniment" },
    { 253, "Accompaniment_Time" },
    { 254, "Activation_Time" },
    { 255, "Active_Authentication_Policy" },
    { 256, "Assigned_Access_Rights" },
    { 257, "Authentication_Factors" },
    { 258, "Authentication_Policy_List" },
    { 259, "Authentication_Policy_Names" },
    { 260, "Authentication_Status" },
    { 261, "Authorization_Mode" },
    { 262, "Belongs_To" },
    { 263, "Credential_Disable" },
    { 264, "Credential_Status" },
    { 265, "Credentials" },
    { 266, "Credentials_In_Zone" },
    { 267, "Days_Remaining" },
    { 268, "Entry_Points" },
    { 269, "Exit_Points" },
    { 270, "Expiration_Time" },
    { 271, "Extended_Time_Enable" },
    { 272, "Failed_Attempt_Events" },
    { 273, "Failed_Attempts" },
    { 274, "Failed_Attempts_Time" },
    { 275, "Last_Access_Event" },
    { 276, "Last_Access_Point" },
    { 277, "Last_Credential_Added" },
    { 278, "Last_Credential_Added_Time" },
    { 279, "Last_Credential_Removed" },
    { 280, "Last_Credential_Removed_Time" },
    { 281, "Last_Use_Time" },
    { 282, "Lockout" },
    { 283, "Lockout_Relinquish_Time" },
    { 285, "Max_Failed_Attempts" },
    { 286, "Members" },
    { 287, "Muster_Point" },
    { 288, "Negative_Access_Rules" },
    { 289, "Number_Of_Authentication_Policies" },
    { 290, "Occupancy_Count" },
    { 291, "Occupancy_Count_Adjust" },
    { 292, "Occupancy_Count_Enable" },
    { 294, "Occupancy_Lower_Limit" },
    { 295, "Occupancy_Lower_Limit_Enforced" },
    { 296, "Occupancy_State" },
    { 297, "Occupancy_Upper_Limit" },
    { 298, "Occupancy_Upper_Limit_Enforced" },
    { 300, "Passback_Mode" },
    { 301, "Passback_Timeout" },
    { 302, "Positive_Access_Rules" },
    { 303, "Reason_For_Disable" },
    { 304, "Supported_Formats" },
    { 305, "Supported_Format_Classes" },
    { 306, "Threat_Authority" },
    { 307, "Threat_Level" },
    { 308, "Trace_Flag" },
    { 309, "Transaction_Notification_Class" },
    { 310, "User_External_Identifier" },
    { 311, "User_Information_Reference" },
    { 317, "User_Name" },
    { 318, "User_Type" },
    { 319, "Uses_Remaining" },
    { 320, "Zone_From" },
    { 321, "Zone_To" },
    { 322, "Access_Event_Tag" },
    { 323, "Global_Identifier" },
    { 326, "Verification_Time" },
    { 327, "Base_Device_Security_Policy" },
    { 328, "Distribution_Key_Revision" },
    { 329, "Do_Not_Hide" },
    { 330, "Key_Sets" },
    { 331, "Last_Key_Server" },
    { 332, "Network_Access_Security_Policies" },
    { 333, "Packet_Reorder_Time" },
    { 334, "Security_Pdu_Timeout" },
    { 335, "Security_Time_Window" },
    { 336, "Supported_Security_Algorithms" },
    { 338, "Backup_And_Restore_State" },
    { 339, "Backup_Preparation_Time" },
    { 340, "Restore_Completion_Time" },
    { 341, "Restore_Preparation_Time" },
    { 342, "Bit_Mask" },
    { 343, "Bit_Text" },
    { 344, "Is_Utc" },
    { 345, "Group_Members" },
    { 346, "Group_Member_Names" },
    { 347, "Member_Status_Flags" },
    { 348, "Requested_Update_Interval" },
    { 349, "Covu_Period" },
    { 350, "Covu_Recipients" },
    { 351, "Event_Message_Texts" },
    { 352, "Event_Message_Texts_Config" },
    { 353, "Event_Detection_Enable" },
    { 354, "Event_Algorithm_Inhibit" },
    { 355, "Event_Algorithm_Inhibit_Ref" },
    { 356, "Time_Delay_Normal" },
    { 357, "Reliability_Evaluation_Inhibit" },
    { 358, "Fault_Parameters" },
    { 359, "Fault_Type" },
    { 360, "Local_Forwarding_Only" },
    { 361, "Process_Identifier_Filter" },
    { 362, "Subscribed_Recipients" },
    { 363, "Port_Filter" },
    { 364, "Authorization_Exemptions" },
    { 365, "Allow_Group_Delay_Inhibit" },
    { 366, "Channel_Number" },
    { 367, "Control_Groups" },
    { 368, "Execution_Delay" },
    { 369, "Last_Priority" },
    { 370, "Write_Status" },
    { 371, "Property_List" },
    { 372, "Serial_Number" },
    { 373, "Blink_Warn_Enable" },
    { 374, "Default_Fade_Time" },
    { 375, "Default_Ramp_Rate" },
    { 376, "Default_Step_Increment" },
    { 377, "Egress_Time" },
    { 378, "In_Progress" },
    { 379, "Instantaneous_Power" },
    { 380, "Lighting_Command" },
    { 381, "Lighting_Command_Default_Priority" },
    { 382, "Max_Actual_Value" },
    { 383, "Min_Actual_Value" },
    { 384, "Power" },
    { 385, "Transition" },
    { 386, "Egress_Active" },
    { 387, "Interface_Value" },
    { 388, "Fault_High_Limit" },
    { 389, "Fault_Low_Limit" },
    { 390, "Low_Diff_Limit" },
    { 391, "Strike_Count" },
    { 392, "Time_Of_Strike_Count_Reset" },
    { 393, "Default_Timeout" },
    { 394, "Initial_Timeout" },
    { 395, "Last_State_Change" },
    { 396, "State_Change_Values" },
    { 397, "Timer_Running" },
    { 398, "Timer_State" },
    { 399, "Apdu_Length" },
    { 400, "Ip_Address" },
    { 401, "Ip_Default_Gateway" },
    { 402, "Ip_Dhcp_Enable" },
    { 403, "Ip_Dhcp_Lease_Time" },
    { 404, "Ip_Dhcp_Lease_Time_Remaining" },
    { 405, "Ip_Dhcp_Server" },
    { 406, "Ip_Dns_Server" },
    { 407, "Bacnet_Ip_Global_Address" },
    { 408, "Bacnet_Ip_Mode" },
    { 409, "Bacnet_Ip_Multicast_Address" },
    { 410, "Bacnet_Ip_Nat_Traversal" },
    { 411, "Ip_Subnet_Mask" },
    { 412, "Bacnet_Ip_Udp_Port" },
    { 413, "Bbmd_Accept_Fd_Registrations" },
    { 414, "Bbmd_Broadcast_Distribution_Table" },
    { 415, "Bbmd_Foreign_Device_Table" },
    { 416, "Changes_Pending" },
    { 417, "Command" },
    { 418, "Fd_Bbmd_Address" },
    { 419, "Fd_Subscription_Lifetime" },
    { 420, "Link_Speed" },
    { 421, "Link_Speeds" },
    { 422, "Link_Speed_Autonegotiate" },
    { 423, "Mac_Address" },
    { 424, "Network_Interface_Name" },
    { 425, "Network_Number" },
    { 426, "Network_Number_Quality" },
    { 427, "Network_Type" },
    { 428, "Routing_Table" },
    { 429, "Virtual_Mac_Address_Table" },
    { 430, "Command_Time_Array" },
    { 431, "Current_Command_Priority" },
    { 432, "Last_Command_Time" },
    { 433, "Value_Source" },
    { 434, "Value_Source_Array" },
    { 435, "Bacnet_Ipv6_Mode" },
    { 436, "Ipv6_Address" },
    { 437, "Ipv6_Prefix_Length" },
    { 438, "Bacnet_Ipv6_Udp_Port" },
    { 439, "Ipv6_Default_Gateway" },
    { 440, "Bacnet_Ipv6_Multicast_Address" },
    { 441, "Ipv6_Dns_Server" },
    { 442, "Ipv6_Auto_Addressing_Enable" },
    { 443, "Ipv6_Dhcp_Lease_Time" },
    { 444, "Ipv6_Dhcp_Lease_Time_Remaining" },
    { 445, "Ipv6_Dhcp_Server" },
    { 446, "Ipv6_Zone_Index" },
    { 447, "Assigned_Landing_Calls" },
    { 448, "Car_Assigned_Direction" },
    { 449, "Car_Door_Command" },
    { 450, "Car_Door_Status" },
    { 451, "Car_Door_Text" },
    { 452, "Car_Door_Zone" },
    { 453, "Car_Drive_Status" },
    { 454, "Car_Load" },
    { 455, "Car_Load_Units" },
    { 456, "Car_Mode" },
    { 457, "Car_Moving_Direction" },
    { 458, "Car_Position" },
    { 459, "Elevator_Group" },
    { 460, "Energy_Meter" },
    { 461, "Energy_Meter_Ref" },
    { 462, "Escalator_Mode" },
    { 463, "Fault_Signals" },
    { 464, "Floor_Text" },
    { 465, "Group_Id" },
    { 467, "Group_Mode" },
    { 468, "Higher_Deck" },
    { 469, "Installation_Id" },
    { 470, "Landing_Calls" },
    { 471, "Landing_Call_Control" },
    { 472, "Landing_Door_Status" },
    { 473, "Lower_Deck" },
    { 474, "Machine_Room_Id" },
    { 475, "Making_Car_Call" },
    { 476, "Next_Stopping_Floor" },
    { 477, "Operation_Direction" },
    { 478, "Passenger_Alarm" },
    { 479, "Power_Mode" },
    { 480, "Registered_Car_Call" },
    { 481, "Active_Cov_Multiple_Subscriptions" },
    { 482, "Protocol_Level" },
    { 483, "Reference_Port" },
    { 484, "Deployed_Profile_Location" },
    { 485, "Profile_Location" },
    { 486, "Tags" },
    { 487, "Subordinate_Node_Types" },
    { 488, "Subordinate_Tags" },
    { 489, "Subordinate_Relationships" },
    { 490, "Default_Subordinate_Relationship" },
    { 491, "Represents" },
    { 492, "Default_Present_Value" },
    { 493, "Present_Stage" },
    { 494, "Stages" },
    { 495, "Stage_Names" },
    { 496, "Target_References" },
    { 497, "Audit_Source_Reporter" },
    { 498, "Audit_Level" },
    { 499, "Audit_Notification_Recipient" },
    { 500, "Audit_Priority_Filter" },
    { 501, "Auditable_Operations" },
    { 502, "Delete_On_Forward" },
    { 503, "Maximum_Send_Delay" },
    { 504, "Monitored_Objects" },
    { 505, "Send_Now" },
    { 506, "Floor_Number" },
    { 507, "Device_Uuid" },
    { 508, "Additional_Reference_Ports" },
    { 509, "Certificate_Signing_Request_File" },
    { 510, "Command_Validation_Result" },
    { 511, "Issuer_Certificate_Files" },
    { 4194304, "Max_Bvlc_Length_Accepted" },
    { 4194305, "Max_Npdu_Length_Accepted" },
    { 4194306, "Operational_Certificate_File" },
    { 4194307, "Current_Health" },
    { 4194308, "Sc_Connect_Wait_Timeout" },
    { 4194309, "Sc_Direct_Connect_Accept_Enable" },
    { 4194310, "Sc_Direct_Connect_Accept_Uris" },
    { 4194311, "Sc_Direct_Connect_Binding" },
    { 4194312, "Sc_Direct_Connect_Connection_Status" },
    { 4194313, "Sc_Direct_Connect_Initiate_Enable" },
    { 4194314, "Sc_Disconnect_Wait_Timeout" },
    { 4194315, "Sc_Failed_Connection_Requests" },
    { 4194316, "Sc_Failover_Hub_Connection_Status" },
    { 4194317, "Sc_Failover_Hub_Uri" },
    { 4194318, "Sc_Hub_Connector_State" },
    { 4194319, "Sc_Hub_Function_Accept_Uris" },
    { 4194320, "Sc_Hub_Function_Binding" },
    { 4194321, "Sc_Hub_Function_Connection_Status" },
    { 4194322, "Sc_Hub_Function_Enable" },
    { 4194323, "Sc_Heartbeat_Timeout" },
    { 4194324, "Sc_Primary_Hub_Connection_Status" },
    { 4194325, "Sc_Primary_Hub_Uri" },
    { 4194326, "Sc_Maximum_Reconnect_Time" },
    { 4194327, "Sc_Minimum_Reconnect_Time" },
    { 4194328, "Color_Override" },
    { 4194329, "Color_Reference" },
    { 4194330, "Default_Color" },
    { 4194331, "Default_Color_Temperature" },
    { 4194332, "Override_Color_Reference" },
    { 4194333, "Write_Every_Scheduled_Action" },
    { 4194334, "Color_Command" },
    { 4194335, "High_End_Trim" },
    { 4194336, "Low_End_Trim" },
    { 4194337, "Trim_Fade_Time" },
    { 4194338, "Device_Address_Proxy_Enable" },
    { 4194339, "Device_Address_Proxy_Table" },
    { 4194340, "Device_Address_Proxy_Timeout" },
    { 4194341, "Default_On_Value" },
    { 4194342, "Last_On_Value" },
    { 4194343, "Authorization_Cache" },
    { 4194344, "Authorization_Groups" },
    { 4194345, "Authorization_Policy" },
    { 4194346, "Authorization_Scope" },
    { 4194347, "Authorization_Server" },
    { 4194348, "Authorization_Status" },
    { 4194349, "Max_Proxied_I_Ams_Per_Second" },
};

const char* LookUpIdName(const IdName* table, size_t count, uint32_t id) {
    size_t lo = 0;
    size_t hi = count;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (table[mid].id == id) {
            return table[mid].name;
        }
        if (table[mid].id < id) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return NULL;
}

const char* ObjectTypeName(uint16_t objectType) {
    return LookUpIdName(OBJECT_TYPE_NAMES, sizeof(OBJECT_TYPE_NAMES) / sizeof(OBJECT_TYPE_NAMES[0]), objectType);
}

const char* PropertyName(uint32_t propertyId) {
    return LookUpIdName(PROPERTY_NAMES, sizeof(PROPERTY_NAMES) / sizeof(PROPERTY_NAMES[0]), propertyId);
}

// --- Generic BACnet tag-header decode (Clause 20.2.1) ------------------------
struct TagHeader {
    uint8_t tagNumber;
    bool contextSpecific;
    bool isOpeningTag;   // constructed-tag opening ("(" - LVT==6)
    bool isClosingTag;   // constructed-tag closing (")" - LVT==7)
    uint32_t length;     // data length for a primitive tag; 0 for opening/closing
    uint32_t headerLength; // bytes the tag header itself occupied
};

// Decodes the tag header starting at frame[offset]. Returns false (leaves
// *out untouched) on truncation or an encoding this decoder doesn't handle -
// every caller treats that as "stop decoding, fall back to what's already
// known" rather than guessing at the rest of the frame.
bool DecodeTagHeader(const uint8_t* frame, uint32_t frameLength, uint32_t offset, TagHeader* out) {
    if (offset >= frameLength) {
        return false;
    }
    uint32_t pos = offset;
    const uint8_t b0 = frame[pos];
    uint8_t tagNumber = (b0 >> 4) & 0x0F;
    const bool contextSpecific = (b0 & 0x08) != 0;
    const uint8_t lvt = b0 & 0x07;
    pos += 1;
    if (tagNumber == 0x0F) { // extended tag number
        if (pos >= frameLength) {
            return false;
        }
        tagNumber = frame[pos];
        pos += 1;
    }
    bool isOpening = false;
    bool isClosing = false;
    uint32_t length = 0;
    if (contextSpecific && lvt == 6) {
        isOpening = true;
    } else if (contextSpecific && lvt == 7) {
        isClosing = true;
    } else if (lvt <= 4) {
        length = lvt;
    } else if (lvt == 5) { // extended length
        if (pos >= frameLength) {
            return false;
        }
        const uint8_t lenByte = frame[pos];
        pos += 1;
        if (lenByte < 254) {
            length = lenByte;
        } else if (lenByte == 254) {
            if (pos + 2 > frameLength) {
                return false;
            }
            length = ((uint32_t)frame[pos] << 8) | frame[pos + 1];
            pos += 2;
        } else {
            if (pos + 4 > frameLength) {
                return false;
            }
            length = ((uint32_t)frame[pos] << 24) | ((uint32_t)frame[pos + 1] << 16) |
                     ((uint32_t)frame[pos + 2] << 8) | frame[pos + 3];
            pos += 4;
        }
    } else {
        return false; // LVT 6/7 without the context-specific bit isn't valid here
    }
    out->tagNumber = tagNumber;
    out->contextSpecific = contextSpecific;
    out->isOpeningTag = isOpening;
    out->isClosingTag = isClosing;
    out->length = length;
    out->headerLength = pos - offset;
    return true;
}

// --- One decode pass shared by the one-line summary and the XML dump --------
// Everything SummarizeBacnetFrame() and the XML dump print comes out of one
// DecodedFrame, built by one walk of the bytes - the two views can never
// disagree with each other about what a frame contains.
struct DecodedFrame {
    bool bacnetIp;          // false: not even a recognizable BVLC header
    uint8_t bvlcFunction;
    bool hasNpdu;           // false for a BVLC control message (no NPDU/APDU)
    uint8_t npduVersion;
    uint8_t npduControl;
    bool hasDest;
    uint16_t dnet;
    const uint8_t* dadr;    // points into the original frame; NULL/0-length = broadcast on dnet
    uint8_t dadrLength;
    bool hasSrc;
    uint16_t snet;
    const uint8_t* sadr;
    uint8_t sadrLength;
    bool isNetworkMessage;
    uint8_t networkMessageType;
    bool hasApdu;
    uint8_t pduType;        // 0-7 per Clause 20.1
    bool segmented;
    bool hasInvokeId;
    uint8_t invokeId;
    bool hasServiceChoice;
    uint8_t serviceChoice;  // confirmed-service-choice for 0/2/3/5; unconfirmed for 1
    bool hasReason;
    uint8_t reason;         // reject reason (pduType 6) or abort reason (pduType 7)
    bool hasObjectProperty;
    uint16_t objectType;
    uint32_t objectInstance;
    uint32_t propertyId;
    bool hasArrayIndex;
    uint32_t arrayIndex;

    DecodedFrame()
        : bacnetIp(false), bvlcFunction(0), hasNpdu(false), npduVersion(0), npduControl(0),
          hasDest(false), dnet(0), dadr(NULL), dadrLength(0), hasSrc(false), snet(0), sadr(NULL),
          sadrLength(0), isNetworkMessage(false), networkMessageType(0), hasApdu(false), pduType(0xFF),
          segmented(false), hasInvokeId(false), invokeId(0), hasServiceChoice(false), serviceChoice(0),
          hasReason(false), reason(0), hasObjectProperty(false), objectType(0), objectInstance(0),
          propertyId(0), hasArrayIndex(false), arrayIndex(0) {}
};

// Shared layout of ReadProperty-Request, ReadProperty-ACK and
// WriteProperty-Request: context tag0 = ObjectIdentifier (4-byte primitive),
// context tag1 = PropertyIdentifier (1-4 byte unsigned), optional context
// tag2 = PropertyArrayIndex (1-4 byte unsigned). Populates the
// ObjectProperty* fields on success; leaves hasObjectProperty false if the
// layout doesn't match, so callers just omit that detail rather than
// printing something wrong.
void DecodeObjectAndProperty(const uint8_t* frame, uint32_t frameLength, uint32_t offset,
                              DecodedFrame* out) {
    TagHeader objTag;
    if (!DecodeTagHeader(frame, frameLength, offset, &objTag) || !objTag.contextSpecific ||
        objTag.tagNumber != 0 || objTag.length != 4 ||
        offset + objTag.headerLength + 4 > frameLength) {
        return;
    }
    const uint32_t objValueOffset = offset + objTag.headerLength;
    const uint32_t objValue = ((uint32_t)frame[objValueOffset] << 24) |
                               ((uint32_t)frame[objValueOffset + 1] << 16) |
                               ((uint32_t)frame[objValueOffset + 2] << 8) |
                               frame[objValueOffset + 3];
    uint32_t pos = objValueOffset + 4;

    TagHeader propTag;
    if (!DecodeTagHeader(frame, frameLength, pos, &propTag) || !propTag.contextSpecific ||
        propTag.tagNumber != 1 || propTag.length == 0 || propTag.length > 4 ||
        pos + propTag.headerLength + propTag.length > frameLength) {
        return;
    }
    pos += propTag.headerLength;
    uint32_t propValue = 0;
    for (uint32_t i = 0; i < propTag.length; ++i) {
        propValue = (propValue << 8) | frame[pos + i];
    }
    pos += propTag.length;

    out->hasObjectProperty = true;
    out->objectType = (uint16_t)((objValue >> 22) & 0x3FF);
    out->objectInstance = objValue & 0x3FFFFF;
    out->propertyId = propValue;

    TagHeader idxTag;
    if (DecodeTagHeader(frame, frameLength, pos, &idxTag) && idxTag.contextSpecific &&
        idxTag.tagNumber == 2 && idxTag.length > 0 && idxTag.length <= 4 &&
        pos + idxTag.headerLength + idxTag.length <= frameLength) {
        uint32_t v = 0;
        for (uint32_t i = 0; i < idxTag.length; ++i) {
            v = (v << 8) | frame[pos + idxTag.headerLength + i];
        }
        out->hasArrayIndex = true;
        out->arrayIndex = v;
    }
}

// Walks BVLC -> NPDU -> APDU exactly as far as needed to fill in 'out';
// never reads past frameLength. See DecodedFrame's comment.
void DecodeBacnetFrame(const uint8_t* frame, uint32_t frameLength, DecodedFrame* out) {
    *out = DecodedFrame();
    if (frame == NULL || frameLength < 4 || frame[0] != 0x81) {
        return;
    }
    out->bacnetIp = true;
    out->bvlcFunction = frame[1];
    uint32_t offset;
    switch (out->bvlcFunction) {
        case 0x0A: // Original-Unicast-NPDU
        case 0x0B: // Original-Broadcast-NPDU
            offset = 4;
            break;
        case 0x04: // Forwarded-NPDU: BVLC header + 6-byte originating address
            offset = 10;
            break;
        default:
            return; // a BVLC control message carries no NPDU/APDU
    }
    if (offset + 2u > frameLength) {
        return;
    }
    out->hasNpdu = true;
    out->npduVersion = frame[offset];
    out->npduControl = frame[offset + 1];
    offset += 2;

    out->hasDest = (out->npduControl & 0x20) != 0;
    out->hasSrc = (out->npduControl & 0x08) != 0;
    out->isNetworkMessage = (out->npduControl & 0x80) != 0;

    if (out->hasDest) {
        if (offset + 3u > frameLength) {
            return;
        }
        out->dnet = (uint16_t)((frame[offset] << 8) | frame[offset + 1]);
        const uint8_t dlen = frame[offset + 2];
        offset += 3;
        if (offset + dlen > frameLength) {
            return;
        }
        out->dadrLength = dlen;
        out->dadr = (dlen > 0) ? &frame[offset] : NULL;
        offset += dlen;
    }
    if (out->hasSrc) {
        if (offset + 3u > frameLength) {
            return;
        }
        out->snet = (uint16_t)((frame[offset] << 8) | frame[offset + 1]);
        const uint8_t slen = frame[offset + 2];
        offset += 3;
        if (offset + slen > frameLength) {
            return;
        }
        out->sadrLength = slen;
        out->sadr = (slen > 0) ? &frame[offset] : NULL;
        offset += slen;
    }
    if (out->hasDest) {
        if (offset >= frameLength) {
            return;
        }
        offset += 1; // hop count, present whenever DNET is (Clause 6.2.2)
    }
    if (offset >= frameLength) {
        return;
    }

    if (out->isNetworkMessage) {
        out->networkMessageType = frame[offset];
        return;
    }

    out->hasApdu = true;
    out->pduType = (frame[offset] >> 4) & 0x0F;
    switch (out->pduType) {
        case 0: { // Confirmed-Request
            out->segmented = (frame[offset] & 0x08) != 0;
            if (offset + 2u >= frameLength) {
                return;
            }
            out->hasInvokeId = true;
            out->invokeId = frame[offset + 2];
            const uint32_t serviceOffset = offset + (out->segmented ? 5u : 3u);
            if (serviceOffset >= frameLength) {
                return;
            }
            out->hasServiceChoice = true;
            out->serviceChoice = frame[serviceOffset];
            if (out->serviceChoice == 12 || out->serviceChoice == 15) { // ReadProperty, WriteProperty
                DecodeObjectAndProperty(frame, frameLength, serviceOffset + 1, out);
            }
            return;
        }
        case 1: { // Unconfirmed-Request
            if (offset + 1u >= frameLength) {
                return;
            }
            out->hasServiceChoice = true;
            out->serviceChoice = frame[offset + 1];
            return;
        }
        case 2: { // SimpleACK
            if (offset + 2u >= frameLength) {
                return;
            }
            out->hasInvokeId = true;
            out->invokeId = frame[offset + 1];
            out->hasServiceChoice = true;
            out->serviceChoice = frame[offset + 2];
            return;
        }
        case 3: { // ComplexACK
            out->segmented = (frame[offset] & 0x08) != 0;
            if (offset + 1u >= frameLength) {
                return;
            }
            out->hasInvokeId = true;
            out->invokeId = frame[offset + 1];
            const uint32_t serviceOffset = offset + (out->segmented ? 4u : 2u);
            if (serviceOffset >= frameLength) {
                return;
            }
            out->hasServiceChoice = true;
            out->serviceChoice = frame[serviceOffset];
            if (out->serviceChoice == 12) { // ReadProperty-ACK
                DecodeObjectAndProperty(frame, frameLength, serviceOffset + 1, out);
            }
            return;
        }
        case 4: // SegmentACK - nothing further to decode
            return;
        case 5: { // Error
            if (offset + 2u >= frameLength) {
                return;
            }
            out->hasInvokeId = true;
            out->invokeId = frame[offset + 1];
            out->hasServiceChoice = true;
            out->serviceChoice = frame[offset + 2];
            return;
        }
        case 6: { // Reject
            if (offset + 2u >= frameLength) {
                return;
            }
            out->hasInvokeId = true;
            out->invokeId = frame[offset + 1];
            out->hasReason = true;
            out->reason = frame[offset + 2];
            return;
        }
        case 7: { // Abort
            if (offset + 2u >= frameLength) {
                return;
            }
            out->hasInvokeId = true;
            out->invokeId = frame[offset + 1];
            out->hasReason = true;
            out->reason = frame[offset + 2];
            return;
        }
        default:
            return;
    }
}

void AppendHex(char* buf, size_t bufLen, const uint8_t* data, uint8_t length) {
    size_t used = strlen(buf);
    for (uint8_t i = 0; i < length && used + 2 < bufLen; ++i) {
        used += (size_t)snprintf(buf + used, bufLen - used, "%02X", data[i]);
    }
}

// Appends " DNET=<n>[ DADR=<hex>]" to 'buf' (nothing if the frame carries no
// destination specifier) - the shared tail for the one-line summary.
void AppendRouteSuffix(char* buf, size_t bufLen, const DecodedFrame& d) {
    if (!d.hasDest) {
        return;
    }
    size_t used = strlen(buf);
    snprintf(buf + used, bufLen - used, " DNET=%u", (unsigned)d.dnet);
    if (d.dadrLength > 0 && d.dadr != NULL) {
        used = strlen(buf);
        snprintf(buf + used, bufLen - used, " DADR=");
        AppendHex(buf, bufLen, d.dadr, d.dadrLength);
    }
}

} // namespace

void CASExampleHelper::SummarizeBacnetFrame(const uint8_t* frame, uint16_t frameLength,
                                             char* outSummary, size_t outSummaryLength) {
    if (outSummary == NULL || outSummaryLength == 0) {
        return;
    }
    outSummary[0] = '\0';

    DecodedFrame d;
    DecodeBacnetFrame(frame, frameLength, &d);
    if (!d.bacnetIp) {
        snprintf(outSummary, outSummaryLength, "?");
        return;
    }
    if (!d.hasNpdu) {
        snprintf(outSummary, outSummaryLength, "BVLC function=0x%02X", (unsigned)d.bvlcFunction);
        return;
    }
    if (d.isNetworkMessage) {
        const char* name = NetworkMessageName(d.networkMessageType);
        if (name != NULL) snprintf(outSummary, outSummaryLength, "Network-Layer-Message: %s", name);
        else snprintf(outSummary, outSummaryLength, "Network-Layer-Message: type=%u", (unsigned)d.networkMessageType);
        AppendRouteSuffix(outSummary, outSummaryLength, d);
        return;
    }
    if (!d.hasApdu) {
        snprintf(outSummary, outSummaryLength, "?");
        return;
    }

    char body[128];
    body[0] = '\0';
    switch (d.pduType) {
        case 0: {
            const char* name = d.hasServiceChoice ? ConfirmedServiceName(d.serviceChoice) : NULL;
            if (!d.hasServiceChoice) snprintf(body, sizeof(body), "ConfirmedRequest");
            else if (name != NULL) snprintf(body, sizeof(body), "ConfirmedRequest: %s", name);
            else snprintf(body, sizeof(body), "ConfirmedRequest: service=%u", (unsigned)d.serviceChoice);
            break;
        }
        case 1: {
            const char* name = d.hasServiceChoice ? UnconfirmedServiceName(d.serviceChoice) : NULL;
            if (!d.hasServiceChoice) snprintf(body, sizeof(body), "Unconfirmed");
            else if (name != NULL) snprintf(body, sizeof(body), "Unconfirmed: %s", name);
            else snprintf(body, sizeof(body), "Unconfirmed: service=%u", (unsigned)d.serviceChoice);
            break;
        }
        case 2: {
            const char* name = d.hasServiceChoice ? ConfirmedServiceName(d.serviceChoice) : NULL;
            if (!d.hasServiceChoice) snprintf(body, sizeof(body), "SimpleACK");
            else if (name != NULL) snprintf(body, sizeof(body), "SimpleACK: %s", name);
            else snprintf(body, sizeof(body), "SimpleACK: service=%u", (unsigned)d.serviceChoice);
            break;
        }
        case 3: {
            const char* name = d.hasServiceChoice ? ConfirmedServiceName(d.serviceChoice) : NULL;
            if (!d.hasServiceChoice) snprintf(body, sizeof(body), "ComplexACK");
            else if (name != NULL) snprintf(body, sizeof(body), "ComplexACK: %s", name);
            else snprintf(body, sizeof(body), "ComplexACK: service=%u", (unsigned)d.serviceChoice);
            break;
        }
        case 4:
            snprintf(body, sizeof(body), "SegmentACK");
            break;
        case 5: {
            const char* name = d.hasServiceChoice ? ConfirmedServiceName(d.serviceChoice) : NULL;
            if (!d.hasServiceChoice) snprintf(body, sizeof(body), "Error");
            else if (name != NULL) snprintf(body, sizeof(body), "Error: %s", name);
            else snprintf(body, sizeof(body), "Error: service=%u", (unsigned)d.serviceChoice);
            break;
        }
        case 6: {
            const char* name = d.hasReason ? RejectReasonName(d.reason) : NULL;
            if (!d.hasReason) snprintf(body, sizeof(body), "Reject");
            else if (name != NULL) snprintf(body, sizeof(body), "Reject: %s", name);
            else snprintf(body, sizeof(body), "Reject: reason=%u", (unsigned)d.reason);
            break;
        }
        case 7: {
            const char* name = d.hasReason ? AbortReasonName(d.reason) : NULL;
            if (!d.hasReason) snprintf(body, sizeof(body), "Abort");
            else if (name != NULL) snprintf(body, sizeof(body), "Abort: %s", name);
            else snprintf(body, sizeof(body), "Abort: reason=%u", (unsigned)d.reason);
            break;
        }
        default:
            snprintf(body, sizeof(body), "?");
            break;
    }

    if (d.hasObjectProperty) {
        const char* typeName = ObjectTypeName(d.objectType);
        const char* propName = PropertyName(d.propertyId);
        const size_t used = strlen(body);
        if (d.hasArrayIndex) {
            if (typeName != NULL && propName != NULL) {
                snprintf(body + used, sizeof(body) - used, " %s %u.%s[%u]",
                         typeName, (unsigned)d.objectInstance, propName, (unsigned)d.arrayIndex);
            } else {
                snprintf(body + used, sizeof(body) - used, " object-type=%u %u.property=%u[%u]",
                         (unsigned)d.objectType, (unsigned)d.objectInstance,
                         (unsigned)d.propertyId, (unsigned)d.arrayIndex);
            }
        } else {
            if (typeName != NULL && propName != NULL) {
                snprintf(body + used, sizeof(body) - used, " %s %u.%s",
                         typeName, (unsigned)d.objectInstance, propName);
            } else {
                snprintf(body + used, sizeof(body) - used, " object-type=%u %u.property=%u",
                         (unsigned)d.objectType, (unsigned)d.objectInstance, (unsigned)d.propertyId);
            }
        }
    }

    snprintf(outSummary, outSummaryLength, "%s", body);
    AppendRouteSuffix(outSummary, outSummaryLength, d);
}

// --- XML frame dump (off by default; ParseXmlLogArg turns it on) -----------
namespace {
bool g_xmlFrameLoggingEnabled = false;
}

void CASExampleHelper::ParseXmlLogArg(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--xmlLog") == 0 || strcmp(argv[i], "--xml") == 0) {
            g_xmlFrameLoggingEnabled = true;
            return;
        }
    }
}

bool CASExampleHelper::IsXmlFrameLoggingEnabled() {
    return g_xmlFrameLoggingEnabled;
}

namespace {

// Prints one indented XML block describing 'frame' to stdout (no leading/
// trailing blank line management beyond what's shown - the caller has
// already printed the "RX/TX <n> bytes ..." prefix with no newline). Very
// verbose by design - this is the deep-debug path, off by default. Always
// includes the full raw hex regardless of how much of the structured decode
// above succeeded, so nothing is ever silently lost (segmented PDUs, a
// service other than ReadProperty/WriteProperty, or the actual property
// VALUE bytes - none of which this decoder parses - are still fully present
// in RawHex for manual inspection).
void PrintFrameAsXml(const uint8_t* frame, uint32_t frameLength) {
    DecodedFrame d;
    DecodeBacnetFrame(frame, frameLength, &d);

    printf("\n  <BACnetMessage bytes=\"%u\">\n", (unsigned)frameLength);
    if (!d.bacnetIp) {
        printf("    <Error>not a recognizable BACnet/IP (BVLC) frame</Error>\n  </BACnetMessage>\n");
        return;
    }
    printf("    <BVLC function=\"0x%02X\"/>\n", (unsigned)d.bvlcFunction);
    if (d.hasNpdu) {
        printf("    <NPDU version=\"%u\" control=\"0x%02X\">\n", (unsigned)d.npduVersion, (unsigned)d.npduControl);
        if (d.hasDest) {
            printf("      <Destination net=\"%u\"", (unsigned)d.dnet);
            if (d.dadrLength > 0 && d.dadr != NULL) {
                printf(" mac=\"");
                for (uint8_t i = 0; i < d.dadrLength; ++i) {
                    printf("%02X", d.dadr[i]);
                }
                printf("\"");
            }
            printf("/>\n");
        }
        if (d.hasSrc) {
            printf("      <Source net=\"%u\"", (unsigned)d.snet);
            if (d.sadrLength > 0 && d.sadr != NULL) {
                printf(" mac=\"");
                for (uint8_t i = 0; i < d.sadrLength; ++i) {
                    printf("%02X", d.sadr[i]);
                }
                printf("\"");
            }
            printf("/>\n");
        }
        if (d.isNetworkMessage) {
            const char* name = NetworkMessageName(d.networkMessageType);
            if (name != NULL) printf("      <NetworkLayerMessage type=\"%u\" name=\"%s\"/>\n", (unsigned)d.networkMessageType, name);
            else printf("      <NetworkLayerMessage type=\"%u\"/>\n", (unsigned)d.networkMessageType);
        } else if (d.hasApdu) {
            static const char* const PDU_TYPE_NAMES[] = {
                "ConfirmedRequest", "UnconfirmedRequest", "SimpleACK", "ComplexACK",
                "SegmentACK", "Error", "Reject", "Abort"
            };
            const char* pduTypeName = (d.pduType < 8) ? PDU_TYPE_NAMES[d.pduType] : "Unknown";
            printf("      <APDU type=\"%s\"", pduTypeName);
            if (d.hasInvokeId) {
                printf(" invokeId=\"%u\"", (unsigned)d.invokeId);
            }
            if (d.hasServiceChoice) {
                const char* name = (d.pduType == 1) ? UnconfirmedServiceName(d.serviceChoice)
                                                      : ConfirmedServiceName(d.serviceChoice);
                if (name != NULL) printf(" service=\"%u\" serviceName=\"%s\"", (unsigned)d.serviceChoice, name);
                else printf(" service=\"%u\"", (unsigned)d.serviceChoice);
            }
            if (d.hasReason) {
                const char* name = (d.pduType == 6) ? RejectReasonName(d.reason) : AbortReasonName(d.reason);
                if (name != NULL) printf(" reason=\"%u\" reasonName=\"%s\"", (unsigned)d.reason, name);
                else printf(" reason=\"%u\"", (unsigned)d.reason);
            }
            if (!d.hasObjectProperty) {
                printf("/>\n");
            } else {
                printf(">\n");
                const char* typeName = ObjectTypeName(d.objectType);
                if (typeName != NULL) printf("        <Object type=\"%u\" typeName=\"%s\" instance=\"%u\"/>\n",
                                              (unsigned)d.objectType, typeName, (unsigned)d.objectInstance);
                else printf("        <Object type=\"%u\" instance=\"%u\"/>\n",
                            (unsigned)d.objectType, (unsigned)d.objectInstance);
                const char* propName = PropertyName(d.propertyId);
                if (propName != NULL) printf("        <Property id=\"%u\" name=\"%s\"/>\n", (unsigned)d.propertyId, propName);
                else printf("        <Property id=\"%u\"/>\n", (unsigned)d.propertyId);
                if (d.hasArrayIndex) {
                    printf("        <ArrayIndex value=\"%u\"/>\n", (unsigned)d.arrayIndex);
                }
                printf("      </APDU>\n");
            }
        }
        printf("    </NPDU>\n");
    }
    printf("    <RawHex>");
    for (uint32_t i = 0; i < frameLength; ++i) {
        printf("%02X", frame[i]);
    }
    printf("</RawHex>\n  </BACnetMessage>\n");
}

} // namespace

void CASExampleHelper::LogBacnetFrame(const uint8_t* frame, uint16_t frameLength) {
    if (g_xmlFrameLoggingEnabled) {
        PrintFrameAsXml(frame, frameLength);
        return;
    }
    char summary[192];
    SummarizeBacnetFrame(frame, frameLength, summary, sizeof(summary));
    printf(" - %s\n", summary);
}


namespace CASExampleHelper {

void RequestRestart(const RestartKind kind, const uint32_t delayMilliseconds) {
    const uint64_t dueAt = MonotonicMilliseconds() + (uint64_t)delayMilliseconds;

    if (g_restartPending) {
        // Never postpone a restart already promised to an earlier client: keep
        // the earliest deadline, and let a Cold request upgrade a pending Warm.
        if (dueAt < g_restartDueAtMs) {
            g_restartDueAtMs = dueAt;
        }
        if (kind == RestartKind::Cold) {
            g_restartKind = RestartKind::Cold;
        }
        return;
    }

    g_restartPending = true;
    g_restartDueAtMs = dueAt;
    g_restartKind = kind;
}

bool RestartDue(RestartKind* const outKind) {
    if (!g_restartPending || MonotonicMilliseconds() < g_restartDueAtMs) {
        return false;
    }
    // Clear BEFORE returning true so this fires exactly once.
    g_restartPending = false;
    if (outKind != NULL) {
        *outKind = g_restartKind;
    }
    return true;
}

void PrintVersion(const char* appName, const char* appVersion) {
    printf("%s v%s\n", appName, appVersion);
    printf("CAS BACnet Stack version: %u.%u.%u.%u\n",
           BACnetStack_GetAPIMajorVersion(), BACnetStack_GetAPIMinorVersion(),
           BACnetStack_GetAPIPatchVersion(), BACnetStack_GetAPIBuildVersion());
    // The vendored common/ helper has its own version (see common/CHANGELOG.md)
    // so it is easy to tell whether this example's copy is stale.
    printf("Common helper (common/) version: %s\n", COMMON_VERSION);
}

// Just the interactive key list, with no version banner - so the two callers that already
// printed one (PrintHelp for the 'h' key, and the --help handler) do not print it twice.
static void PrintInteractiveCommands() {
    printf("Commands:\n");
    printf("  h     - show this help (version + commands)\n");
    printf("  q     - quit\n");
    printf("  up    - increase Analog Input 1 by 1.1\n");
    printf("  down  - decrease Analog Input 1 by 1.1\n");
}

void PrintHelp(const char* appName, const char* appVersion) {
    PrintVersion(appName, appVersion);
    PrintInteractiveCommands();
}

bool HandleHelpAndVersionArgs(const int argc, char** argv, const char* appName, const char* appVersion,
                              const bool showDccPasswordCliOption) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0 ||
            strcmp(argv[i], "/?") == 0) {
            PrintVersion(appName, appVersion);
            printf("\n");
            printf("Usage: <executable> [options]\n");
            printf("\n");
            printf("Options:\n");
            printf("  --help, -h        Show this help and exit.\n");
            printf("  --version         Show version information and exit.\n");
            printf("  --deviceID <n>    BACnet device instance (0..4194302). Each example in\n");
            printf("                    this series has its own default so several can run on\n");
            printf("                    one subnet at once.\n");
            printf("  --port <n>        BACnet/IP UDP port (1..65535). Default 47808 (0xBAC0).\n");
            printf("                    Use a non-default port to avoid clashing with another\n");
            printf("                    BACnet device already on 47808 on this host.\n");
            if (showDccPasswordCliOption) {
                printf("  --dcc-password <string>\n");
                printf("                    DeviceCommunicationControl password. Default \"\" (no\n");
                printf("                    password required). Set to require a matching password on\n");
                printf("                    DeviceCommunicationControl requests - see this example's own\n");
                printf("                    DeviceCommunicationControl callback for how it is checked.\n");
            }
            printf("  --xml             Print every RX/TX BACnet message as an indented XML\n");
            printf("                    block instead of a one-line summary. Off by default -\n");
            printf("                    very verbose, meant for deep protocol debugging.\n");
            printf("\n");
            PrintInteractiveCommands(); // version banner already printed above
            return true;
        }
        if (strcmp(argv[i], "--version") == 0) {
            PrintVersion(appName, appVersion);
            return true;
        }
    }
    return false;
}

const char* ParseDccPasswordArg(const int argc, char** argv, const char* defaultPassword) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--dcc-password") == 0) {
            return argv[i + 1]; // argv's own storage outlives main() - safe to return directly
        }
    }
    return defaultPassword;
}

// Parse a whole-number argument value. Returns true only if the ENTIRE token is
// a valid non-negative integer. This exists because atoi()/atol() silently
// return 0 on garbage - so `--deviceID abc` would parse as device 0, a valid
// instance, and the operator would ship a device answering at the wrong address
// with no diagnostic. strtol + an end-pointer check is the difference between
// "rejected your typo" and "silently obeyed a different command than you gave".
static bool ParseWholeNumber(const char* text, long* out) {
    if (text == NULL || *text == '\0') {
        return false;
    }
    char* end = NULL;
    errno = 0;
    const long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0) {
        return false; // non-numeric, trailing junk, empty, negative, or overflow
    }
    *out = value;
    return true;
}

uint16_t ParsePortArg(const int argc, char** argv, const uint16_t defaultPort) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--port") == 0) {
            long p = 0;
            if (ParseWholeNumber(argv[i + 1], &p) && p > 0 && p <= 65535) {
                return (uint16_t)p;
            }
            printf("Warning: ignoring invalid --port \"%s\" (want 1..65535); using %u.\n",
                   argv[i + 1], (unsigned)defaultPort);
        }
    }
    return defaultPort;
}

uint32_t ParseDeviceIdArg(const int argc, char** argv, const uint32_t defaultDeviceId) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--deviceID") == 0) {
            // 0 .. 4194302 is the valid BACnet device instance range (4194303 is
            // the "unconfigured" wildcard and is not a usable instance).
            long id = 0;
            if (ParseWholeNumber(argv[i + 1], &id) && id < 4194303) {
                return (uint32_t)id;
            }
            printf("Warning: ignoring invalid --deviceID \"%s\" (want 0..4194302); using %u.\n",
                   argv[i + 1], (unsigned)defaultDeviceId);
        }
    }
    return defaultDeviceId;
}

bool SetupUDP(const uint16_t port, const uint32_t networkPortInstance) {
    UdpBinding* binding = FindUdpBindingByInstance(networkPortInstance);
    if (binding == NULL) {
        if (g_udpBindingCount >= MAX_UDP_BINDINGS) {
            printf("Error: SetupUDP: MAX_UDP_BINDINGS (%u) already bound; "
                   "raise it in CASExampleHelper.cpp if you need more ports.\n",
                   (unsigned)MAX_UDP_BINDINGS);
            return false;
        }
        binding = &g_udpBindings[g_udpBindingCount++];
        binding->networkPortInstance = networkPortInstance;
    }
    if (!binding->udp.Connect(port)) {
        printf("Error: Failed to bind UDP port %u (Network Port %u).\n",
               (unsigned)port, (unsigned)networkPortInstance);
        return false;
    }
    binding->port = port;
    binding->bound = true;
    if (networkPortInstance == g_networkPortInstance) {
        // Keep g_port in step for the single-argument SendIAm(deviceInstance).
        g_port = port;
    }
    printf("FYI: Listening for BACnet/IP on UDP port %u (Network Port %u).\n",
           (unsigned)port, (unsigned)networkPortInstance);
    return true;
}

bool SetupUDP(const uint16_t port) {
    return SetupUDP(port, g_networkPortInstance);
}

void ShutdownUDP() {
    for (size_t i = 0; i < g_udpBindingCount; ++i) {
        if (g_udpBindings[i].bound) {
            g_udpBindings[i].udp.Disconnect();
            g_udpBindings[i].bound = false;
        }
    }
}

void SetNetworkPortInstance(const uint32_t networkPortInstance) {
    g_networkPortInstance = networkPortInstance;
}

void RegisterCommonCallbacks() {
    BACnetStack_RegisterCallbackReceiveMessageForPort(HelperReceiveMessage);
    BACnetStack_RegisterCallbackSendMessageForPort(HelperSendMessage);
    BACnetStack_RegisterCallbackGetSystemTime(HelperGetSystemTime);
}

bool GetLocalIPv4(uint8_t ipAddress[4], uint8_t subnetMask[4]) {
    return GetPrimaryIPv4(ipAddress, subnetMask);
}

bool GetLocalLinkSpeedBitsPerSecond(double* bitsPerSecond) {
    return GetPrimaryLinkSpeedBitsPerSecond(bitsPerSecond);
}

void SendIAm(const uint32_t deviceInstance, const uint32_t networkPortInstance) {
    // Target the LOCAL subnet broadcast (the device's own network) rather than
    // the global 255.255.255.255 / network 0xFFFF. The broadcast is ip | ~mask
    // of the primary IPv4 interface - the same network the Network Port object
    // represents - falling back to the limited broadcast if it can't be found.
    //
    // NOTE for multi-port examples: every Network Port in this series' examples
    // runs on the SAME host interface (different UDP ports simulate different
    // BACnet/IP networks), so the primary-interface broadcast address is the
    // right target for every instance; only the port differs, taken from that
    // instance's own binding below.
    uint8_t bcast[4] = { 255, 255, 255, 255 };
    uint8_t ip[4], mask[4];
    if (GetPrimaryIPv4(ip, mask)) {
        bcast[0] = (uint8_t)(ip[0] | ~mask[0]);
        bcast[1] = (uint8_t)(ip[1] | ~mask[1]);
        bcast[2] = (uint8_t)(ip[2] | ~mask[2]);
        bcast[3] = (uint8_t)(ip[3] | ~mask[3]);
    }

    const UdpBinding* binding = FindUdpBindingByInstance(networkPortInstance);
    const uint16_t port = (binding != NULL && binding->bound) ? binding->port : g_port;

    const uint8_t connectionString[6] = {
        bcast[0], bcast[1], bcast[2], bcast[3],
        (uint8_t)((port >> 8) & 0xFF), (uint8_t)(port & 0xFF)
    };
    // destinationNetwork 0 = the local network only (not the global 0xFFFF).
    BACnetStack_SendIAm(deviceInstance, connectionString, 6,
                        networkPortInstance,
                        true /*broadcast*/, 0 /*local network*/, NULL, 0);
}

void SendIAm(const uint32_t deviceInstance) {
    SendIAm(deviceInstance, g_networkPortInstance);
}

KeyCommand PollKey() {
#if defined(_WIN32)
    if (!_kbhit()) {
        return KeyCommand::None;
    }
    const int c = _getch();
    if (c == 0 || c == 0xE0) {           // arrow / function key prefix
        const int c2 = _getch();
        if (c2 == 72) return KeyCommand::ArrowUp;
        if (c2 == 80) return KeyCommand::ArrowDown;
        return KeyCommand::None;
    }
    if (c == 'h' || c == 'H') return KeyCommand::Help;
    if (c == 'q' || c == 'Q') return KeyCommand::Quit;
    if (c == 's' || c == 'S') return KeyCommand::DemoAdvance;
    if (c == 'w' || c == 'W') return KeyCommand::WriteGroupDemo;
    if (c == 'd' || c == 'D') return KeyCommand::DiscoverRemote;
    if (c == 'r' || c == 'R') return KeyCommand::RouterAnnounce;
    if (c == 'm' || c == 'M') return KeyCommand::Metrics;
    return KeyCommand::None;
#else
    EnableRawInput();
    unsigned char buf[3];
    const int n = (int)read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) {
        return KeyCommand::None;
    }
    if (n >= 3 && buf[0] == 27 && buf[1] == '[') { // ESC [ A/B = arrow keys
        if (buf[2] == 'A') return KeyCommand::ArrowUp;
        if (buf[2] == 'B') return KeyCommand::ArrowDown;
        return KeyCommand::None;
    }
    if (buf[0] == 'h' || buf[0] == 'H') return KeyCommand::Help;
    if (buf[0] == 'q' || buf[0] == 'Q') return KeyCommand::Quit;
    if (buf[0] == 's' || buf[0] == 'S') return KeyCommand::DemoAdvance;
    if (buf[0] == 'w' || buf[0] == 'W') return KeyCommand::WriteGroupDemo;
    if (buf[0] == 'd' || buf[0] == 'D') return KeyCommand::DiscoverRemote;
    if (buf[0] == 'r' || buf[0] == 'R') return KeyCommand::RouterAnnounce;
    if (buf[0] == 'm' || buf[0] == 'M') return KeyCommand::Metrics;
    return KeyCommand::None;
#endif
}

void RestoreInput() {
#if !defined(_WIN32)
    if (g_rawActive) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_origTermios);
        g_rawActive = false;
    }
#endif
}

} // namespace CASExampleHelper
