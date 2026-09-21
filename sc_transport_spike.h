// SPDX-License-Identifier: CC0-1.0
// =============================================================================
// PHASE 1 SPIKE - TEMPORARY - see docs/bacnet-sc-transport-plan.md.
//
// This file (and sc_transport_spike.cpp) exist only to settle, empirically on
// this machine, which libwebsockets Service() mechanism is non-blocking on
// Windows (options a/b/c in the plan), and to prove the vcpkg + CMake wiring
// for libwebsockets/OpenSSL actually links cleanly against the CAS BACnet
// Stack (SOURCE mode, static CRT) in the same executable.
//
// It is NOT part of the real sc_transport/ architecture - that lands in
// Phase 2/3. This file is expected to be deleted once ScTransport.h/.cpp
// exist and main.cpp's --sc-spike hook below is removed.
// =============================================================================
#pragma once

// Runs the lws Service() spike and prints its findings to stdout.
// Returns 0 on success (even if the finding is "must fall back to a worker
// thread") - a non-zero return means the spike itself could not run (e.g.
// lws context creation failed).
int RunScTransportSpike();
