// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_SERVICE_H
#define BSCHUB_EXAMPLE_SERVICE_H

// service.h
// =============================================================================
// Running the hub unattended (issue #34):
//
//   Windows - as a Windows service:
//     BACnetExampleBSCHUB --install-service --config C:\ProgramData\...\hub.conf
//         registers the service "BACnetSCHub" (start on boot, restart on
//         failure) to run "BACnetExampleBSCHUB --service --config <that file>".
//         Needs an Administrator prompt.
//     BACnetExampleBSCHUB --uninstall-service
//         stops and removes it.
//     --service is what the Service Control Manager runs; it is not for use
//     from a console. The hub then runs with the config file's folder as its
//     working directory, so relative paths in the config file (sc-cert-dir,
//     log-file) are relative to it.
//
//   Linux/macOS - under systemd (packaging/linux/bacnet-schub-hub.service) or
//   any supervisor: SIGTERM (systemctl stop) and SIGINT (Ctrl+C) stop the hub
//   cleanly, the same as pressing 'q'.
//
// main() hands its body to Run(), which calls it directly, or from the
// service's own thread when started with --service. The main loop polls
// StopRequested() every tick.
// =============================================================================

namespace Service {

// Handles --install-service / --uninstall-service. Returns true (with
// *exitCode set) if one of them was given - main() then just returns.
bool HandleServiceCommand(int argc, char** argv, int* exitCode);

// Runs `hub(argc, argv)`: as a Windows service if --service is given (Windows
// only), otherwise directly, with SIGTERM/SIGINT wired to StopRequested().
// Returns the hub's exit code.
int Run(int argc, char** argv, int (*hub)(int, char**));

// True once the service was told to stop, or SIGTERM/SIGINT arrived.
bool StopRequested();

// True when running as a Windows service (no console: don't poll keys).
bool IsService();

}  // namespace Service

#endif  // BSCHUB_EXAMPLE_SERVICE_H
