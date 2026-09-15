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

// The single UDP socket shared by the transport callbacks. The stack calls the
// callbacks as plain C function pointers (no user-data argument), so the socket
// lives here as a file-local singleton rather than being passed in. This is a
// deliberate simplification for the example; an application that needs multiple
// datalinks would route through its own context object instead.
SimpleUDP g_udp;

// The BACnet/IP port the device is bound to (used to address broadcast I-Am).
uint16_t g_port = 47808;

// The instance of the Network Port object that owns this UDP socket. The stack
// identifies a link by its Network Port object INSTANCE, not by a transport
// network type, so the transport callbacks and SendIAm all have to name it.
// The example's main() tells us which one it added, via
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
    if (maxConnectionStringLength < 6) {
        return 0;
    }

    uint8_t fromIp[4];
    uint16_t fromPort = 0;
    // Receive() copies at most maxMessageLength bytes; a datagram larger than the
    // stack's buffer is truncated to that length (fine for UDP - the stack will
    // simply fail to decode and ignore an over-length frame).
    const uint16_t bytesRead = g_udp.Receive(message, maxMessageLength, fromIp, &fromPort);
    if (bytesRead == 0) {
        return 0; // no datagram waiting
    }

    printf("RX %u bytes from %u.%u.%u.%u:%u\n", (unsigned)bytesRead,
           fromIp[0], fromIp[1], fromIp[2], fromIp[3], (unsigned)fromPort);

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
    // answer on the port a request came in on. This example has exactly one
    // port, so it always reports that one - see SetNetworkPortInstance().
    *networkPortInstance = g_networkPortInstance;
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
    // used to name the transport's network type). This example serves exactly
    // one port, so anything else is not ours to send.
    if (networkPortInstance != g_networkPortInstance ||
        connectionStringLength < 6) {
        return 0;
    }

    const uint8_t ip[4] = { connectionString[0], connectionString[1],
                            connectionString[2], connectionString[3] };
    const uint16_t port = (uint16_t)((connectionString[4] << 8) | connectionString[5]);

    const uint16_t sent = g_udp.Send(ip, port, message, messageLength);
    printf("TX %u bytes to %u.%u.%u.%u:%u%s\n", (unsigned)sent,
           ip[0], ip[1], ip[2], ip[3], (unsigned)port,
           broadcast ? " (broadcast)" : "");
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

bool HandleHelpAndVersionArgs(const int argc, char** argv, const char* appName, const char* appVersion) {
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

bool SetupUDP(const uint16_t port) {
    g_port = port;
    if (!g_udp.Connect(port)) {
        printf("Error: Failed to bind UDP port %u.\n", (unsigned)port);
        return false;
    }
    printf("FYI: Listening for BACnet/IP on UDP port %u.\n", (unsigned)port);
    return true;
}

void ShutdownUDP() {
    g_udp.Disconnect();
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

void SendIAm(const uint32_t deviceInstance) {
    // Target the LOCAL subnet broadcast (the device's own network) rather than
    // the global 255.255.255.255 / network 0xFFFF. The broadcast is ip | ~mask
    // of the primary IPv4 interface - the same network the Network Port object
    // represents - falling back to the limited broadcast if it can't be found.
    uint8_t bcast[4] = { 255, 255, 255, 255 };
    uint8_t ip[4], mask[4];
    if (GetPrimaryIPv4(ip, mask)) {
        bcast[0] = (uint8_t)(ip[0] | ~mask[0]);
        bcast[1] = (uint8_t)(ip[1] | ~mask[1]);
        bcast[2] = (uint8_t)(ip[2] | ~mask[2]);
        bcast[3] = (uint8_t)(ip[3] | ~mask[3]);
    }

    const uint8_t connectionString[6] = {
        bcast[0], bcast[1], bcast[2], bcast[3],
        (uint8_t)((g_port >> 8) & 0xFF), (uint8_t)(g_port & 0xFF)
    };
    // destinationNetwork 0 = the local network only (not the global 0xFFFF).
    BACnetStack_SendIAm(deviceInstance, connectionString, 6,
                        g_networkPortInstance,
                        true /*broadcast*/, 0 /*local network*/, NULL, 0);
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
