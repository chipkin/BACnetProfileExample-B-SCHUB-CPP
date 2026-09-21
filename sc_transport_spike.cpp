// SPDX-License-Identifier: CC0-1.0
// PHASE 1 SPIKE - TEMPORARY - see sc_transport_spike.h and
// docs/bacnet-sc-transport-plan.md. Not part of the real transport.
#include "sc_transport_spike.h"

#include <libwebsockets.h>

#include <chrono>
#include <cstdio>
#include <thread>

namespace {

// Creates a minimal, non-listening (CONTEXT_PORT_NO_LISTEN) lws context with
// zero pending connections/I/O, so any blocking behaviour in the mechanism
// under test is caused by the mechanism itself, not by real work to do.
lws_context* CreateSpikeContext() {
    lws_context_creation_info info{};
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    return lws_create_context(&info);
}

// Calls `serviceOnce` at ~1ms intervals for ~2 seconds with no pending I/O,
// printing worst-case and average per-call elapsed time. Returns true if
// every call returned in well under 1ms (non-blocking pass).
template <typename ServiceFn>
bool TimeService(const char* label, lws_context* ctx, ServiceFn serviceOnce) {
    const int kIterations = 2000;  // ~2s at 1ms spacing
    double worstMs = 0.0;
    double totalMs = 0.0;
    for (int i = 0; i < kIterations; ++i) {
        const auto start = std::chrono::steady_clock::now();
        serviceOnce(ctx);
        const auto end = std::chrono::steady_clock::now();
        const double ms = std::chrono::duration<double, std::milli>(end - start).count();
        worstMs = (ms > worstMs) ? ms : worstMs;
        totalMs += ms;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const double avgMs = totalMs / kIterations;
    printf("  [%s] %d calls: avg=%.4fms worst=%.4fms\n", label, kIterations, avgMs, worstMs);
    // "Well under 1ms" - use 1ms as the pass/fail line for worst-case.
    return worstMs < 1.0;
}

}  // namespace

int RunScTransportSpike() {
    printf("=== BACnet/SC transport spike: lws Service() mechanism ===\n");
    printf("lws version: %s\n", lws_get_library_version());

    lws_context* ctx = CreateSpikeContext();
    if (!ctx) {
        fprintf(stderr, "spike: lws_create_context failed\n");
        return 1;
    }

    printf("(a) lws_cancel_service(ctx); lws_service(ctx, 0):\n");
    const bool aPass = TimeService("a", ctx, [](lws_context* c) {
        lws_cancel_service(c);
        lws_service(c, 0);
    });
    printf("  (a) %s\n", aPass ? "PASS (non-blocking)" : "FAIL (blocked)");

    printf("(b) lws_service(ctx, -1):\n");
    const bool bPass = TimeService("b", ctx, [](lws_context* c) { lws_service(c, -1); });
    printf("  (b) %s\n", bPass ? "PASS (non-blocking)" : "FAIL (blocked)");

    lws_context_destroy(ctx);

    printf("=== Finding: %s ===\n",
           aPass  ? "(a) lws_cancel_service+lws_service(0) is non-blocking - use it."
           : bPass ? "(b) lws_service(-1) is non-blocking - use it."
                   : "(a) and (b) both block - fall back to (c) worker thread.");
    return 0;
}
