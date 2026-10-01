// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// ScDiagnostics.cpp - see ScDiagnostics.h.

#include "ScDiagnostics.h"

#include <time.h>

#include <deque>
#include <mutex>

namespace CASSc {
namespace ScDiagnostics {
namespace {

std::mutex g_mutex;
std::deque<Event> g_events;
uint64_t g_nextSequence = 1;

std::string UtcNow() {
    const time_t now = time(nullptr);
    struct tm t;
#if defined(_WIN32)
    gmtime_s(&t, &now);
#else
    gmtime_r(&now, &t);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &t);
    return buf;
}

}  // namespace

void Record(const std::string& kind, const std::string& address, const std::string& subject,
            const std::string& issuer, const std::string& detail) {
    Event e;
    e.time = UtcNow();
    e.kind = kind;
    e.address = address;
    e.subject = subject;
    e.issuer = issuer;
    e.detail = detail;
    std::lock_guard<std::mutex> lock(g_mutex);
    e.sequence = g_nextSequence++;
    g_events.push_back(e);
    while (g_events.size() > kMaxEvents) {
        g_events.pop_front();
    }
}

std::vector<Event> Since(uint64_t after) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::vector<Event> out;
    for (const Event& e : g_events) {
        if (e.sequence > after) {
            out.push_back(e);
        }
    }
    return out;
}

}  // namespace ScDiagnostics
}  // namespace CASSc
