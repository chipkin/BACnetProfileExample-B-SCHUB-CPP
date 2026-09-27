// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// log_file.cpp - see log_file.h for what this does and why.

#include "log_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
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

std::string g_path;
uint64_t g_maxBytes = 0;
unsigned g_maxFiles = 0;

FILE* g_file = nullptr;
uint64_t g_fileBytes = 0;

int g_pipeRead = -1;
int g_pipeWrite = -1;
int g_consoleOut = -1;  // the original stdout, so output still reaches the console
int g_consoleErr = -1;  // the original stderr
int g_outFd = 1;        // the descriptors stdout/stderr write to (see Start: not always 1 and 2)
int g_errFd = 2;
std::thread g_thread;
std::atomic<bool> g_running(false);

// When rotating or reopening fails (another program holds the file open, the
// disk is full), wait this long before trying again rather than on every
// write - retrying immediately would shift away the archives one by one.
const std::chrono::seconds kRetryInterval(30);
std::chrono::steady_clock::time_point g_nextRetry;

// A problem with the log file itself goes to the console only (writing it to
// stdout would loop straight back into the pipe).
void ReportToConsole(const std::string& message) {
    const int fd = g_consoleErr >= 0 ? g_consoleErr : g_consoleOut;
    if (fd >= 0) {
        const std::string line = "[log-file] " + message + "\n";
        LOG_WRITE(fd, line.data(), (unsigned)line.size());
    }
}

bool OpenFile() {
    g_file = fopen(g_path.c_str(), "ab");
    if (g_file == nullptr) {
        return false;
    }
    fseek(g_file, 0, SEEK_END);
    const long size = ftell(g_file);
    g_fileBytes = size > 0 ? (uint64_t)size : 0;
    return true;
}

// <path>.N -> <path>.N+1 (dropping the oldest), <path> -> <path>.1, new <path>.
// The live file is moved aside FIRST: if that fails (on Windows, another
// program has it open), nothing else is touched - the archives are kept, the
// file keeps growing for now, and rotation is retried after kRetryInterval.
void Rotate() {
    fclose(g_file);
    g_file = nullptr;
    const std::string aside = g_path + ".rotating";
    remove(aside.c_str());
    if (rename(g_path.c_str(), aside.c_str()) != 0) {
        ReportToConsole("could not rotate \"" + g_path + "\" (is another program holding it open?); "
                        "will retry - the file grows past log-max-size-mb until then");
        g_nextRetry = std::chrono::steady_clock::now() + kRetryInterval;
    } else if (g_maxFiles == 0) {
        remove(aside.c_str());
    } else {
        remove((g_path + "." + std::to_string(g_maxFiles)).c_str());
        for (unsigned n = g_maxFiles; n > 1; --n) {
            rename((g_path + "." + std::to_string(n - 1)).c_str(), (g_path + "." + std::to_string(n)).c_str());
        }
        rename(aside.c_str(), (g_path + ".1").c_str());
    }
    if (!OpenFile()) {
        ReportToConsole("could not reopen \"" + g_path + "\"; will retry");
        g_nextRetry = std::chrono::steady_clock::now() + kRetryInterval;
    }
}

void Append(const char* data, const size_t length) {
    if (g_file != nullptr && length > 0) {
        fwrite(data, 1, length, g_file);
        fflush(g_file);
        g_fileBytes += length;
    }
}

// Writes `data`, rotating first if it would take the file past maxBytes. The
// cut is made after the last complete line that still fits, so no line is
// split between two files.
void WriteToFile(const char* data, const size_t length) {
    const bool retryDue = std::chrono::steady_clock::now() >= g_nextRetry;
    if (g_file == nullptr) {
        if (!retryDue || !OpenFile()) {
            if (retryDue) {
                g_nextRetry = std::chrono::steady_clock::now() + kRetryInterval;
            }
            return;  // the console still gets everything
        }
        ReportToConsole("logging to \"" + g_path + "\" again");
    }
    if (g_maxBytes == 0 || g_fileBytes + length <= g_maxBytes || !retryDue) {
        Append(data, length);
        return;
    }
    size_t head = 0;  // bytes up to and including the last newline that fits
    for (size_t i = 0; i < length && g_fileBytes + i < g_maxBytes; ++i) {
        if (data[i] == '\n') {
            head = i + 1;
        }
    }
    Append(data, head);
    if (g_fileBytes > 0) {
        Rotate();
    }
    Append(data + head, length - head);
}

// Copies the pipe to the console and the log file until the write end closes.
void CopyLoop() {
    char buffer[4096];
    for (;;) {
        const int n = LOG_READ(g_pipeRead, buffer, (unsigned)sizeof(buffer));
        if (n <= 0) {
            break;
        }
        if (g_consoleOut >= 0) {
            LOG_WRITE(g_consoleOut, buffer, (unsigned)n);
        }
        WriteToFile(buffer, (size_t)n);
    }
}

}  // namespace

bool Start(const std::string& path, const uint64_t maxBytes, const unsigned maxFiles) {
    if (g_running) {
        return true;
    }
    g_path = path;
    g_maxBytes = maxBytes;
    g_maxFiles = maxFiles;
    if (!OpenFile()) {
        fprintf(stderr, "Error: could not open --log-file \"%s\" for appending; logging to the console only.\n",
                path.c_str());
        return false;
    }

    int fds[2];
#if defined(_WIN32)
    if (_pipe(fds, 64 * 1024, _O_BINARY) != 0) {
#else
    if (pipe(fds) != 0) {
#endif
        fprintf(stderr, "Error: could not create the --log-file pipe; logging to the console only.\n");
        fclose(g_file);
        g_file = nullptr;
        return false;
    }
    g_pipeRead = fds[0];
    g_pipeWrite = fds[1];

    fflush(stdout);
    fflush(stderr);
#if defined(_WIN32)
    // A Windows service (or any process started without a console) has no
    // standard handles: stdout and stderr then have no file descriptor at all
    // (_fileno() < 0), so pointing descriptors 1 and 2 at the pipe would catch
    // nothing and the log file would stay empty. Give them one first (NUL),
    // and redirect whichever descriptor they actually got.
    if (_fileno(stdout) < 0 && freopen("NUL", "w", stdout) != NULL) {
        setvbuf(stdout, NULL, _IONBF, 0);  // freopen resets the unbuffered mode RunHub set
    }
    if (_fileno(stderr) < 0 && freopen("NUL", "w", stderr) != NULL) {
        setvbuf(stderr, NULL, _IONBF, 0);
    }
    g_outFd = _fileno(stdout) >= 0 ? _fileno(stdout) : 1;
    g_errFd = _fileno(stderr) >= 0 ? _fileno(stderr) : 2;
#endif
    g_consoleOut = LOG_DUP(g_outFd);
    g_consoleErr = LOG_DUP(g_errFd);
    // Both streams go to the one pipe, so the file keeps their order. The
    // copy thread writes everything to the console's stdout.
    LOG_DUP2(g_pipeWrite, g_outFd);
    LOG_DUP2(g_pipeWrite, g_errFd);

    g_running = true;
    g_thread = std::thread(CopyLoop);
    // Every way out of the process - a "return 1" from an early error, exit(),
    // the normal shutdown - must stop the copy thread first: a std::thread
    // still joinable when static destructors run calls std::terminate.
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
    // Put the console back on 1 and 2, then close every write end of the pipe
    // so the copy thread reads end-of-file and finishes. With no console to
    // put back (a service can start without one, so the _dup in Start failed),
    // just close 1 and 2 - they are write ends of the pipe too.
    if (g_consoleOut >= 0) {
        LOG_DUP2(g_consoleOut, g_outFd);
    } else {
        LOG_CLOSE(g_outFd);
    }
    if (g_consoleErr >= 0) {
        LOG_DUP2(g_consoleErr, g_errFd);
    } else {
        LOG_CLOSE(g_errFd);
    }
    LOG_CLOSE(g_pipeWrite);
    g_pipeWrite = -1;
    if (g_thread.joinable()) {
        g_thread.join();
    }
    LOG_CLOSE(g_pipeRead);
    g_pipeRead = -1;
    if (g_consoleOut >= 0) {
        LOG_CLOSE(g_consoleOut);
    }
    if (g_consoleErr >= 0) {
        LOG_CLOSE(g_consoleErr);
    }
    g_consoleOut = g_consoleErr = -1;
    if (g_file != nullptr) {
        fclose(g_file);
        g_file = nullptr;
    }
}

}  // namespace LogFile
