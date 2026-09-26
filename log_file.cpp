// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// log_file.cpp - see log_file.h for what this does and why.

#include "log_file.h"

#include <stdio.h>
#include <string.h>

#include <atomic>
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
std::thread g_thread;
std::atomic<bool> g_running(false);

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
void Rotate() {
    fclose(g_file);
    g_file = nullptr;
    if (g_maxFiles == 0) {
        remove(g_path.c_str());
    } else {
        remove((g_path + "." + std::to_string(g_maxFiles)).c_str());
        for (unsigned n = g_maxFiles; n > 1; --n) {
            rename((g_path + "." + std::to_string(n - 1)).c_str(), (g_path + "." + std::to_string(n)).c_str());
        }
        rename(g_path.c_str(), (g_path + ".1").c_str());
    }
    OpenFile();
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
    if (g_file == nullptr) {
        return;
    }
    if (g_maxBytes == 0 || g_fileBytes + length <= g_maxBytes) {
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
    g_consoleOut = LOG_DUP(1);
    g_consoleErr = LOG_DUP(2);
    // Both streams go to the one pipe, so the file keeps their order. The
    // copy thread writes everything to the console's stdout.
    LOG_DUP2(g_pipeWrite, 1);
    LOG_DUP2(g_pipeWrite, 2);

    g_running = true;
    g_thread = std::thread(CopyLoop);
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
    // so the copy thread reads end-of-file and finishes.
    LOG_DUP2(g_consoleOut, 1);
    LOG_DUP2(g_consoleErr, 2);
    LOG_CLOSE(g_pipeWrite);
    g_pipeWrite = -1;
    if (g_thread.joinable()) {
        g_thread.join();
    }
    LOG_CLOSE(g_pipeRead);
    g_pipeRead = -1;
    LOG_CLOSE(g_consoleOut);
    LOG_CLOSE(g_consoleErr);
    g_consoleOut = g_consoleErr = -1;
    if (g_file != nullptr) {
        fclose(g_file);
        g_file = nullptr;
    }
}

}  // namespace LogFile
