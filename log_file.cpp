// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// log_file.cpp - see log_file.h for what this does and why.

#include "log_file.h"

#include <stdio.h>
#include <stdlib.h>

#include <filesystem>
#include <system_error>
#include <thread>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <share.h>  // _SH_DENYWR
#define LOG_DUP _dup
#define LOG_DUP2 _dup2
#define LOG_READ _read
#define LOG_WRITE _write
#define LOG_CLOSE _close
#else
#include <unistd.h>
#define LOG_DUP dup
#define LOG_DUP2 dup2
#define LOG_READ read
#define LOG_WRITE write
#define LOG_CLOSE close
#endif

namespace LogFile {
namespace {

FILE* g_file = nullptr;
int g_pipeRead = -1;
int g_pipeWrite = -1;
int g_consoleOut = -1;  // the original stdout: everything is still shown on the console
int g_consoleErr = -1;  // the original stderr, put back by Stop()
std::thread g_thread;
bool g_running = false;

// Copies the pipe to the console and the log file until every write end of
// the pipe is closed (Stop()).
void CopyLoop() {
    char buffer[4096];
    for (;;) {
        const int n = LOG_READ(g_pipeRead, buffer, (unsigned)sizeof(buffer));
        if (n <= 0) {
            break;
        }
        LOG_WRITE(g_consoleOut, buffer, (unsigned)n);
        fwrite(buffer, 1, (size_t)n, g_file);
        fflush(g_file);  // a crash or a kill still leaves everything so far in the file
    }
}

}  // namespace

bool Start(const std::string& folder, const std::string& fileName, std::string* fullPath) {
    if (g_running) {
        return true;
    }
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::create_directories(folder, ec);
    const fs::path path = fs::absolute(fs::path(folder) / fileName, ec);
    *fullPath = path.string();

    // "wb": truncate - each start-up begins a new log. On Windows, others may
    // read the file while the example runs, but not write it (so a second
    // copy started in the same folder logs to its console only).
#if defined(_WIN32)
    g_file = _fsopen(fullPath->c_str(), "wb", _SH_DENYWR);
#else
    g_file = fopen(fullPath->c_str(), "wb");
#endif
    if (g_file == nullptr) {
        fprintf(stderr, "Error: could not create the log file \"%s\"; logging to the console only.\n",
                fullPath->c_str());
        return false;
    }

    int fds[2];
#if defined(_WIN32)
    const int pipeResult = _pipe(fds, 64 * 1024, _O_BINARY);
#else
    const int pipeResult = pipe(fds);
#endif
    if (pipeResult != 0) {
        fprintf(stderr, "Error: could not set up the log file; logging to the console only.\n");
        fclose(g_file);
        g_file = nullptr;
        return false;
    }
    g_pipeRead = fds[0];
    g_pipeWrite = fds[1];

    // Keep the console, then point stdout and stderr at the pipe. Both go to
    // the one pipe, so the file keeps their order; the copy thread shows
    // everything on the console's stdout.
    fflush(stdout);
    fflush(stderr);
    g_consoleOut = LOG_DUP(1);
    g_consoleErr = LOG_DUP(2);
    if (g_consoleOut < 0 || LOG_DUP2(g_pipeWrite, 1) < 0 || LOG_DUP2(g_pipeWrite, 2) < 0) {
        fprintf(stderr, "Error: could not capture the console for the log file; logging to the console only.\n");
        if (g_consoleOut >= 0) {
            LOG_DUP2(g_consoleOut, 1);
            LOG_CLOSE(g_consoleOut);
        }
        if (g_consoleErr >= 0) {
            LOG_DUP2(g_consoleErr, 2);
            LOG_CLOSE(g_consoleErr);
        }
        g_consoleOut = g_consoleErr = -1;
        LOG_CLOSE(g_pipeRead);
        LOG_CLOSE(g_pipeWrite);
        g_pipeRead = g_pipeWrite = -1;
        fclose(g_file);
        g_file = nullptr;
        return false;
    }

    g_running = true;
    g_thread = std::thread(CopyLoop);
    // Every way out of the process - an early "return 1", exit(), the normal
    // end of main() - must stop the copy thread first: a std::thread still
    // running when static destructors run calls std::terminate.
    static bool registered = false;
    if (!registered) {
        registered = true;
        atexit(Stop);
    }
    return true;
}

void Stop() {
    if (!g_running) {
        return;
    }
    g_running = false;
    fflush(stdout);
    fflush(stderr);
    // Put the console back on 1 and 2 and close the last write end of the
    // pipe, so the copy thread reads end-of-file and finishes.
    LOG_DUP2(g_consoleOut, 1);
    if (g_consoleErr >= 0) {
        LOG_DUP2(g_consoleErr, 2);
    }
    LOG_CLOSE(g_pipeWrite);
    g_pipeWrite = -1;
    if (g_thread.joinable()) {
        g_thread.join();
    }
    LOG_CLOSE(g_pipeRead);
    g_pipeRead = -1;
    LOG_CLOSE(g_consoleOut);
    if (g_consoleErr >= 0) {
        LOG_CLOSE(g_consoleErr);
    }
    g_consoleOut = g_consoleErr = -1;
    fclose(g_file);
    g_file = nullptr;
}

}  // namespace LogFile
