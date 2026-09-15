// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
#ifndef CAS_EXAMPLE_HELPER_H
#define CAS_EXAMPLE_HELPER_H

// CASExampleHelper.h
// =============================================================================
// Shared boilerplate for every CAS BACnet Stack example project.
//
// The goal of these examples is that each profile's main.cpp reads like a
// tutorial: device setup, the objects it exposes, and the property callbacks -
// nothing else. All the "plumbing" that is identical for every example lives
// here:
//
//   * The UDP socket on the BACnet/IP port and the three transport/time
//     callbacks the stack always needs (receive, send, get-system-time).
//   * Printing version information (the example's version + the stack's).
//   * Parsing the common command-line options (e.g. --port).
//   * Reading the common keyboard commands (h / q / arrow up / arrow down).
//   * Sending an unsolicited I-Am on start-up.
//
// This folder is generic and is copied verbatim into each example repository.
// It carries its own version (COMMON_VERSION below) and its own changelog
// (common/CHANGELOG.md) so an example can tell whether its copy is stale.
// To change it: edit it, bump COMMON_VERSION, record the change in
// common/CHANGELOG.md, then re-copy common/ into EVERY example in the series.
//
// The CAS BACnet Stack is linked via the C++ adapter (CASBACnetStackAdapter.h) -
// BACnetStack_* is called directly, the same call whether the stack is compiled from
// source, linked as a static lib, or loaded from a DLL/.so. The example's main() must
// call LoadBACnetFunctions() once, before any BACnetStack_* call, in every mode.
// =============================================================================

#include <stdint.h>

namespace CASExampleHelper {

// --- Version / help --------------------------------------------------------
// The version of the vendored common/ helper itself (NOT the example's
// version). Bump it whenever anything in common/ changes, and record the
// change in common/CHANGELOG.md - every example in the series must then be
// re-synced to the same common/ version.
static const char* COMMON_VERSION = "2.5.0";

// Print the example's name + version, the linked CAS BACnet Stack version,
// and the common/ helper version.
void PrintVersion(const char* appName, const char* appVersion);

// Print the version information plus the list of interactive key commands.
// (This is what the 'h' key shows.)
void PrintHelp(const char* appName, const char* appVersion);

// --- Command line ----------------------------------------------------------
// Handle the two options that exit instead of running: --help and --version.
// Call this FIRST in main(), before binding a socket or touching the stack:
//
//     if (CASExampleHelper::HandleHelpAndVersionArgs(argc, argv, APP_NAME, APP_VERSION)) {
//         return 0;
//     }
//
// Returns true if it printed something and the caller should exit(0); false to
// carry on starting up. Every example in the series supports --help/--version,
// so this lives here rather than in each main.cpp.
bool HandleHelpAndVersionArgs(int argc, char** argv, const char* appName, const char* appVersion);

// Return the UDP port to use: the value after "--port" if present, else
// defaultPort. Common to every example.
uint16_t ParsePortArg(int argc, char** argv, uint16_t defaultPort);

// Return the device instance to use: the value after "--deviceID" if present,
// else defaultDeviceId. BACnet requires a device's instance to be configurable.
// Common to every example.
uint32_t ParseDeviceIdArg(int argc, char** argv, uint32_t defaultDeviceId);

// --- Networking ------------------------------------------------------------
// Bind the UDP socket used by the CURRENT Network Port instance (the one last
// named by SetNetworkPortInstance(), or instance 1 if that was never called -
// the series convention for a single-port example). This is the entry point
// every single-port example has always used; its behaviour is unchanged by
// the multi-port support below: it binds exactly one socket, keyed to exactly
// one Network Port instance, exactly as before 2.3.0.
bool SetupUDP(uint16_t port);

// Bind an ADDITIONAL UDP socket for a SPECIFIC Network Port object instance -
// added in common/ 2.3.0 for examples that own more than one BACnet/IP link
// (e.g. a router example with a Network Port per side). Call once per port,
// each with a different networkPortInstance. Internally this is the same
// per-instance binding SetupUDP(port) uses for the "current" instance; the
// two overloads share one small table (CASExampleHelper.cpp), so mixing them
// is safe - SetupUDP(port) is exactly SetupUDP(port, <current instance>).
//
// The receive callback polls every bound socket in round-robin order each
// tick (so one busy port cannot starve another) and reports the instance the
// datagram arrived on; the send callback looks up the socket whose instance
// matches the one the stack names. A single-port example has exactly one
// entry in that table, so both callbacks collapse back to "the one socket" -
// see the "WHY THIS IS SAFE FOR SINGLE-PORT EXAMPLES" comment in
// CASExampleHelper.cpp.
bool SetupUDP(uint16_t port, uint32_t networkPortInstance);

// Close every UDP socket bound by SetupUDP() (all instances).
void ShutdownUDP();

// Tell the helper which Network Port object instance is "current" - the one
// the single-argument SetupUDP(port) and SendIAm(deviceInstance) overloads
// act on.
//
// The stack identifies a link by the INSTANCE of its Network Port object, not
// by a transport network type: the receive callback reports the instance a
// datagram arrived on, the send callback is told the instance to send from,
// and SendIAm is told which port to announce on.
//
// Call this once, after BACnetStack_AddNetworkPortObject() and before
// RegisterCommonCallbacks(). It defaults to 1 - the series convention - so an
// example that uses instance 1 need not call it, but calling it explicitly
// keeps main.cpp's Network Port instance the single source of truth. A
// multi-port example (SetupUDP(port, instance) for two or more instances)
// still calls this once, for whichever instance should be "current" for the
// single-argument SetupUDP()/SendIAm() overloads - typically its first port.
void SetNetworkPortInstance(uint32_t networkPortInstance);

// Register the transport + system-time callbacks (backed by the UDP socket
// created in SetupUDP, so call SetupUDP first).
void RegisterCommonCallbacks();

// Broadcast an unsolicited I-Am for the given device on the CURRENT Network
// Port instance (see SetNetworkPortInstance). ANSI/ASHRAE 135 requires a
// device to announce itself with I-Am on start-up. Unchanged since before
// 2.3.0 for a single-port example.
void SendIAm(uint32_t deviceInstance);

// Broadcast an unsolicited I-Am for the given device on a SPECIFIC Network
// Port instance - added in common/ 2.3.0 for a multi-port example that must
// announce itself once per port/network it serves. SendIAm(deviceInstance) is
// exactly SendIAm(deviceInstance, <current instance>).
void SendIAm(uint32_t deviceInstance, uint32_t networkPortInstance);

// Get the primary IPv4 interface's address and subnet mask (each as 4 octets).
// These are the values a BACnet/IP Network Port object reports (IP_Address,
// IP_Subnet_Mask), and the broadcast (ip | ~mask) is the I-Am target. Returns
// true on success; on failure the buffers are left untouched.
bool GetLocalIPv4(uint8_t ipAddress[4], uint8_t subnetMask[4]);

// --- Deferred device restart (DM-RD-B) -------------------------------------
// Only for examples whose profile includes DM-RD-B (i.e. that register a
// ReinitializeDevice callback). Most profiles in this series do not.
//
// WHY THIS EXISTS. A ReinitializeDevice callback must NOT restart the device
// inside the callback. Returning true only tells the stack the request was
// accepted - the SimpleACK is encoded now but does not reach the wire until a
// later BACnetStack_Tick(). Restart (or exit, or reset) before that tick and
// the ACK is never transmitted: the client sees a timeout and reports the
// device as unresponsive, even though it did exactly what it was told. That is
// the classic DM-RD-B interop bug, and it fails BTL.
//
// The fix is to defer: the callback records "a restart is due at time T" and
// returns immediately; the main loop performs the restart once T has passed, by
// which point the ACK has been sent. The delay also gives the client's own
// request timer a chance to complete cleanly.
//
// Usage - in the ReinitializeDevice callback, after it decides to accept:
//
//     CASExampleHelper::RequestRestart(CASExampleHelper::RestartKind::Cold,
//                                      CASExampleHelper::RESTART_DELAY_MS);
//     return true;   // let the stack ACK first
//
// ...and once per tick in the main loop, after BACnetStack_Tick():
//
//     CASExampleHelper::RestartKind kind;
//     if (CASExampleHelper::RestartDue(&kind)) {
//         // a real device reboots here; see main.cpp for what this example does
//     }

enum class RestartKind {
    Cold,   // REINITIALIZE_STATE_COLDSTART - full power-on restart
    Warm    // REINITIALIZE_STATE_WARMSTART - re-initialize, keep what survives
};

// A restart delay that is comfortably longer than one tick of the main loop,
// so the SimpleACK is on the wire before anything is torn down. One second is
// the conventional choice: long enough to be safe on a busy or slow link,
// short enough that the operator sees the device go down promptly.
static const uint32_t RESTART_DELAY_MS = 1000;

// Record that a restart of the given kind is due delayMilliseconds from now.
// Safe to call more than once: the EARLIEST pending deadline wins, so a second
// ReinitializeDevice arriving during the delay window cannot postpone a restart
// that was already promised to the first client. A Cold request also upgrades a
// pending Warm one (cold is the stronger reset); the reverse does not downgrade.
void RequestRestart(RestartKind kind, uint32_t delayMilliseconds);

// Call once per tick of the main loop. Returns true EXACTLY ONCE - on the first
// call after the deadline has passed - and writes the requested kind to
// *outKind. Returns false when no restart is pending or the delay has not yet
// elapsed. Clearing the request before returning true means a caller that
// handles the restart in-process (rather than actually rebooting) does not get
// a second one on the next tick.
bool RestartDue(RestartKind* outKind);

// --- Keyboard input (common to every example) ------------------------------
enum class KeyCommand {
    None,        // nothing pressed
    Help,        // 'h' - show version + commands
    Quit,        // 'q' - exit
    ArrowUp,     // up arrow
    ArrowDown,   // down arrow
    DemoAdvance,   // 's' - advance a demo (e.g. a Schedule) to its next step now,
                   //       bypassing whatever wall-clock wait it would otherwise need
    WriteGroupDemo,// 'w' - manually fire a demo WriteGroup (or other outbound
                   //       SendWriteProperty) instead of waiting for whatever
                   //       triggers it normally
    DiscoverRemote, // 'd' - send a demo SendWhoIs to discover a remote device
                    //       this example writes to or reads from
    RouterAnnounce  // 'r' - manually (re-)send I-Am-Router-To-Network now, instead
                     //       of waiting for the one sent at start-up, so routing
                     //       can be demonstrated on demand
};

// Non-blocking: returns a pending key command, or None if nothing was pressed.
// Call once per tick of the main loop.
KeyCommand PollKey();

// Restore the terminal to its normal mode (POSIX); no-op on Windows. Call once
// before the program exits.
void RestoreInput();

} // namespace CASExampleHelper

#endif // CAS_EXAMPLE_HELPER_H
