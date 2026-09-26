// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// service.cpp - see service.h for what this does and why.

#include "service.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <atomic>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#include <direct.h>
#endif

namespace Service {
namespace {

std::atomic<bool> g_stopRequested(false);
bool g_isService = false;

void OnStopSignal(int) {
    g_stopRequested = true;
}

bool HasArg(const int argc, char** argv, const char* name) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], name) == 0) {
            return true;
        }
    }
    return false;
}

std::string ArgValue(const int argc, char** argv, const char* name) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], name) == 0) {
            return argv[i + 1];
        }
    }
    return std::string();
}

#if defined(_WIN32)
const char* const SERVICE_NAME = "BACnetSCHub";
const char* const SERVICE_DISPLAY_NAME = "BACnet/SC Hub (Chipkin B-SCHUB example)";
const char* const SERVICE_DESCRIPTION =
    "BACnet Secure Connect hub built on the CAS BACnet Stack. See the manual for configuration.";

SERVICE_STATUS_HANDLE g_statusHandle = NULL;
SERVICE_STATUS g_status;
int g_argc = 0;
char** g_argv = NULL;
int (*g_hub)(int, char**) = NULL;
int g_exitCode = 0;

void ReportStatus(const DWORD state, const DWORD exitCode, const DWORD waitHintMs) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint = waitHintMs;
    SetServiceStatus(g_statusHandle, &g_status);
}

DWORD WINAPI ControlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 10000);
        g_stopRequested = true;
    }
    return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, LPSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExA(SERVICE_NAME, ControlHandler, NULL);
    if (g_statusHandle == NULL) {
        return;
    }
    memset(&g_status, 0, sizeof(g_status));
    ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    g_exitCode = g_hub(g_argc, g_argv);
    // A non-zero exit is reported as a service-specific error, which the
    // failure actions set at install time answer by restarting the service.
    ReportStatus(SERVICE_STOPPED, g_exitCode == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR, 0);
}

// Relative paths in the config file (sc-cert-dir, log-file) are relative to
// the config file's folder; a service would otherwise start in System32.
void ChangeToConfigDirectory(const std::string& configPath) {
    char full[MAX_PATH];
    char* filePart = NULL;
    if (configPath.empty() || GetFullPathNameA(configPath.c_str(), MAX_PATH, full, &filePart) == 0 ||
        filePart == NULL) {
        return;
    }
    *filePart = '\0';
    _chdir(full);
}

int InstallService(const int argc, char** argv) {
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        fprintf(stderr, "Error: could not find this program's own path.\n");
        return 1;
    }
    std::string command = std::string("\"") + exePath + "\" --service";
    const std::string config = ArgValue(argc, argv, "--config");
    if (!config.empty()) {
        char full[MAX_PATH];
        if (GetFullPathNameA(config.c_str(), MAX_PATH, full, NULL) == 0) {
            fprintf(stderr, "Error: could not resolve --config \"%s\".\n", config.c_str());
            return 1;
        }
        command += std::string(" --config \"") + full + "\"";
    } else {
        fprintf(stderr, "Warning: no --config given; the service will run with the built-in defaults "
                        "and ./certs relative to %s.\n", exePath);
    }

    SC_HANDLE manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (manager == NULL) {
        fprintf(stderr, "Error: could not open the Service Control Manager (error %lu). Run this from an "
                        "Administrator command prompt.\n", GetLastError());
        return 1;
    }
    SC_HANDLE service = CreateServiceA(manager, SERVICE_NAME, SERVICE_DISPLAY_NAME, SERVICE_ALL_ACCESS,
                                       SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                       command.c_str(), NULL, NULL, NULL, NULL, NULL);
    if (service == NULL) {
        const DWORD error = GetLastError();
        fprintf(stderr, "Error: could not create the service (error %lu%s).\n", error,
                error == ERROR_SERVICE_EXISTS ? ": it is already installed - --uninstall-service first" : "");
        CloseServiceHandle(manager);
        return 1;
    }
    SERVICE_DESCRIPTIONA description = {const_cast<char*>(SERVICE_DESCRIPTION)};
    ChangeServiceConfig2A(service, SERVICE_CONFIG_DESCRIPTION, &description);
    // Restart on failure: after 5 s, then 30 s, then every 60 s.
    SC_ACTION actions[3] = {{SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 30000}, {SC_ACTION_RESTART, 60000}};
    SERVICE_FAILURE_ACTIONSA failure;
    memset(&failure, 0, sizeof(failure));
    failure.dwResetPeriod = 24 * 60 * 60;
    failure.cActions = 3;
    failure.lpsaActions = actions;
    ChangeServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure);
    SERVICE_FAILURE_ACTIONS_FLAG failureFlag = {TRUE};  // also restart after a non-zero exit
    ChangeServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failureFlag);
    printf("Installed the \"%s\" service: %s\nStart it with: sc start %s\n", SERVICE_NAME, command.c_str(),
           SERVICE_NAME);
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return 0;
}

int UninstallService() {
    SC_HANDLE manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (manager == NULL) {
        fprintf(stderr, "Error: could not open the Service Control Manager (error %lu). Run this from an "
                        "Administrator command prompt.\n", GetLastError());
        return 1;
    }
    SC_HANDLE service = OpenServiceA(manager, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (service == NULL) {
        fprintf(stderr, "Error: the \"%s\" service is not installed (error %lu).\n", SERVICE_NAME, GetLastError());
        CloseServiceHandle(manager);
        return 1;
    }
    SERVICE_STATUS status;
    if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        for (int i = 0; i < 100 && QueryServiceStatus(service, &status) && status.dwCurrentState != SERVICE_STOPPED; ++i) {
            Sleep(100);
        }
    }
    const bool deleted = DeleteService(service) != 0;
    if (deleted) {
        printf("Removed the \"%s\" service.\n", SERVICE_NAME);
    } else {
        fprintf(stderr, "Error: could not remove the service (error %lu).\n", GetLastError());
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return deleted ? 0 : 1;
}
#endif

}  // namespace

bool HandleServiceCommand(const int argc, char** argv, int* exitCode) {
    const bool install = HasArg(argc, argv, "--install-service");
    const bool uninstall = HasArg(argc, argv, "--uninstall-service");
    if (!install && !uninstall) {
        return false;
    }
#if defined(_WIN32)
    *exitCode = install ? InstallService(argc, argv) : UninstallService();
#else
    fprintf(stderr, "Error: --install-service/--uninstall-service are for Windows. On Linux, use the systemd "
                    "unit in packaging/linux/ (see the manual).\n");
    *exitCode = 1;
#endif
    return true;
}

int Run(const int argc, char** argv, int (*hub)(int, char**)) {
    signal(SIGINT, OnStopSignal);
    signal(SIGTERM, OnStopSignal);
#if defined(_WIN32)
    if (HasArg(argc, argv, "--service")) {
        g_isService = true;
        g_argc = argc;
        g_argv = argv;
        g_hub = hub;
        ChangeToConfigDirectory(ArgValue(argc, argv, "--config"));
        SERVICE_TABLE_ENTRYA table[] = {{const_cast<char*>(SERVICE_NAME), ServiceMain}, {NULL, NULL}};
        if (!StartServiceCtrlDispatcherA(table)) {
            fprintf(stderr, "Error: --service is only for the Windows Service Control Manager (error %lu). "
                            "Install it with --install-service.\n", GetLastError());
            return 1;
        }
        return g_exitCode;
    }
#endif
    return hub(argc, argv);
}

bool StopRequested() {
    return g_stopRequested;
}

bool IsService() {
    return g_isService;
}

}  // namespace Service
