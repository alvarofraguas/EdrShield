/*
 * EdrShield - WFP/QoS Tamper Protection (Community Edition)
 * Main entry point
 *
 * MIT License
 */

#include "edrshield.h"

static void PrintBanner(void) {
    printf("\n");
    printf("  EdrShield v%s (Community Edition)\n", EDRSHIELD_VERSION);
    printf("  Defender WFP/QoS tamper protection\n\n");
}

static void PrintUsage(void) {
    PrintBanner();
    printf("  Usage: edrshield.exe <command>\n\n");
    printf("  Service:\n");
    printf("    install       Install as Windows service (auto-start on boot)\n");
    printf("    uninstall     Stop and remove the service\n");
    printf("    start         Start the service\n");
    printf("    stop          Stop the service\n");
    printf("    status        Show service state and WFP/QoS summary\n");
    printf("\n");
    printf("  Diagnostics:\n");
    printf("    scan          One-shot scan for hostile filters/policies\n");
    printf("    monitor       Run monitor in foreground (Ctrl+C to stop)\n");
    printf("    protect       Register protective PERMIT filters\n");
    printf("    version       Show version\n");
    printf("    help          Show this help\n");
    printf("\n");
    printf("  Requires: Administrator privileges\n");
    printf("  Logs to:  %s\n", LOG_FILE);
    printf("  Events:   Windows Event Log (source: %s)\n\n", EVENT_SOURCE);
}

static void CmdScan(void) {
    HANDLE engine = NULL;
    if (WfpEngineOpen(&engine) != ERROR_SUCCESS) return;

    WfpDiscoverTrustedProviders(engine);
    printf("\n  === WFP Scan (%d trusted providers) ===\n\n",
           WfpGetTrustedProviderCount());

    HOSTILE_FILTER hostiles[512];
    int wfpCount = WfpScanHostileFilters(engine, hostiles, 512);

    if (wfpCount == 0) {
        printf("  [OK] No hostile WFP filters detected.\n");
    } else {
        printf("  [!!] %d HOSTILE WFP FILTERS FOUND:\n\n", wfpCount);
        for (int i = 0; i < wfpCount; i++) {
            printf("    #%d  ID: %llu\n", i + 1,
                   (unsigned long long)hostiles[i].filterId);
            printf("        Name:     %ls\n", hostiles[i].filterName);
            printf("        Target:   %s\n", hostiles[i].vendor);
            printf("        Provider: %s\n", hostiles[i].providerInfo);
            printf("        App:      %ls\n", hostiles[i].appPath);
            printf("\n");
        }
    }

    printf("\n  === QoS Scan ===\n\n");

    char qosNames[128][256];
    int qosCount = QosScanHostilePolicies(qosNames, 128);

    if (qosCount == 0) {
        printf("  [OK] No hostile QoS policies detected.\n");
    } else {
        printf("  [!!] %d HOSTILE QoS POLICIES FOUND:\n\n", qosCount);
        for (int i = 0; i < qosCount; i++) {
            printf("    #%d  Name: %s\n", i + 1, qosNames[i]);
        }
    }

    printf("\n  Run 'edrshield.exe monitor' to auto-remediate.\n\n");
    WfpEngineClose(engine);
}

static void CmdStart(void) {
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) {
        printf("[!] Cannot open SCM (run as admin)\n");
        return;
    }
    SC_HANDLE hSvc = OpenServiceW(hScm, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        printf("[!] Service not installed. Run 'edrshield.exe install' first.\n");
        CloseServiceHandle(hScm);
        return;
    }

    SERVICE_STATUS status;
    QueryServiceStatus(hSvc, &status);
    if (status.dwCurrentState == SERVICE_RUNNING) {
        printf("[*] Service is already running.\n");
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return;
    }

    if (StartServiceW(hSvc, 0, NULL)) {
        printf("[+] Service starting...\n");
        for (int i = 0; i < 10; i++) {
            Sleep(500);
            QueryServiceStatus(hSvc, &status);
            if (status.dwCurrentState == SERVICE_RUNNING) {
                printf("[+] Service started.\n");
                break;
            }
        }
        if (status.dwCurrentState != SERVICE_RUNNING)
            printf("[*] Service is still starting (state=%lu)\n", status.dwCurrentState);
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
            printf("[*] Service is already running.\n");
        else
            printf("[!] StartService failed: 0x%08lX\n", err);
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

static void CmdStop(void) {
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) {
        printf("[!] Cannot open SCM (run as admin)\n");
        return;
    }
    SC_HANDLE hSvc = OpenServiceW(hScm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        printf("[!] Service not installed.\n");
        CloseServiceHandle(hScm);
        return;
    }

    SERVICE_STATUS status;
    QueryServiceStatus(hSvc, &status);
    if (status.dwCurrentState == SERVICE_STOPPED) {
        printf("[*] Service is already stopped.\n");
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return;
    }

    if (ControlService(hSvc, SERVICE_CONTROL_STOP, &status)) {
        printf("[+] Stopping service...\n");
        for (int i = 0; i < 10; i++) {
            Sleep(500);
            QueryServiceStatus(hSvc, &status);
            if (status.dwCurrentState == SERVICE_STOPPED) {
                printf("[+] Service stopped.\n");
                break;
            }
        }
        if (status.dwCurrentState != SERVICE_STOPPED)
            printf("[*] Service is still stopping (state=%lu)\n", status.dwCurrentState);
    } else {
        printf("[!] StopService failed: 0x%08lX\n", GetLastError());
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

static const char *ServiceStateStr(DWORD state) {
    switch (state) {
        case SERVICE_STOPPED:          return "STOPPED";
        case SERVICE_START_PENDING:    return "STARTING";
        case SERVICE_STOP_PENDING:     return "STOPPING";
        case SERVICE_RUNNING:          return "RUNNING";
        case SERVICE_CONTINUE_PENDING: return "RESUMING";
        case SERVICE_PAUSE_PENDING:    return "PAUSING";
        case SERVICE_PAUSED:           return "PAUSED";
        default:                       return "UNKNOWN";
    }
}

static void CmdStatus(void) {
    HANDLE engine = NULL;
    if (WfpEngineOpen(&engine) != ERROR_SUCCESS) return;

    printf("\n");
    printf("  ═══════════════════════════════════════════\n");
    printf("  EdrShield v%s - Status\n", EDRSHIELD_VERSION);
    printf("  ═══════════════════════════════════════════\n\n");

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm) {
        SC_HANDLE hSvc = OpenServiceW(hScm, SERVICE_NAME, SERVICE_QUERY_STATUS);
        if (hSvc) {
            SERVICE_STATUS svcStatus;
            if (QueryServiceStatus(hSvc, &svcStatus))
                printf("  [i]  Service: %s\n",
                       ServiceStateStr(svcStatus.dwCurrentState));
            else
                printf("  [i]  Service: query failed\n");
            CloseServiceHandle(hSvc);
        } else {
            printf("  [i]  Service: NOT INSTALLED\n");
        }
        CloseServiceHandle(hScm);
    }

    WfpDiscoverTrustedProviders(engine);
    printf("  [i]  Trusted WFP providers: %d\n", WfpGetTrustedProviderCount());

    HOSTILE_FILTER hostiles[512];
    int hostileCount = WfpScanHostileFilters(engine, hostiles, 512);

    if (hostileCount > 0)
        printf("  [!!] Hostile WFP filters: %d\n", hostileCount);
    else
        printf("  [OK] Hostile WFP filters: 0\n");

    HANDLE enumHandle = NULL;
    int protectiveCount = 0;

    if (FwpmFilterCreateEnumHandle0(engine, NULL, &enumHandle) == ERROR_SUCCESS) {
        FWPM_FILTER0 **filters = NULL;
        UINT32 numFilters = 0;
        if (FwpmFilterEnum0(engine, enumHandle, MAX_FILTERS_ENUM,
                            &filters, &numFilters) == ERROR_SUCCESS && filters) {
            for (UINT32 i = 0; i < numFilters; i++) {
                if (WfpIsOurFilter(filters[i])) protectiveCount++;
            }
            FwpmFreeMemory0((void **)&filters);
        }
        FwpmFilterDestroyEnumHandle0(engine, enumHandle);
    }

    printf("  [i]  Protective PERMIT filters: %d\n", protectiveCount);

    DISCOVERED_EDR edrs[MAX_EDR_PROCESSES];
    int edrCount = DiscoverRunningEDRs(edrs, MAX_EDR_PROCESSES);
    printf("  [i]  Running EDR processes: %d\n\n", edrCount);

    if (edrCount > 0) {
        printf("  Detected EDR processes:\n");
        for (int i = 0; i < edrCount; i++) {
            printf("    %-30s  %-15s  PID=%lu\n",
                   edrs[i].exeName, edrs[i].vendor,
                   (unsigned long)edrs[i].pid);
        }
        printf("\n");
    }

    char qosNames[128][256];
    int qosCount = QosScanHostilePolicies(qosNames, 128);
    if (qosCount > 0)
        printf("  [!!] Hostile QoS policies: %d\n", qosCount);
    else
        printf("  [OK] Hostile QoS policies: 0\n");

    printf("\n  ═══════════════════════════════════════════\n\n");
    WfpEngineClose(engine);
}

static BOOL g_consoleRunning = TRUE;

static BOOL WINAPI ConsoleHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        g_consoleRunning = FALSE;
        return TRUE;
    }
    return FALSE;
}

static void CmdMonitor(void) {
    HANDLE engine = NULL;
    if (WfpEngineOpen(&engine) != ERROR_SUCCESS) return;

    WfpRegisterProvider(engine);
    WfpRegisterSublayer(engine);

    Log(LOG_INFO, "=== EdrShield v%s console monitor ===", EDRSHIELD_VERSION);

    WfpDiscoverTrustedProviders(engine);
    Log(LOG_INFO, "Trusted providers cached: %d", WfpGetTrustedProviderCount());

    int protCount = ProtectAllDiscoveredEDRs(engine);
    Log(LOG_INFO, "Initial: %d PERMIT filters registered", protCount);

    WriteEventLog(EVENTLOG_INFORMATION_TYPE, EVT_MONITOR_STARTED,
        "EdrShield console monitor started");

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    HANDLE stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    int cycles = 0;
    while (g_consoleRunning) {
        cycles++;

        HOSTILE_FILTER hostiles[512];
        int wfpFound = WfpScanHostileFilters(engine, hostiles, 512);

        if (wfpFound > 0) {
            Log(LOG_ALERT, "=== %d HOSTILE WFP FILTERS ===", wfpFound);
            int removed = WfpRemediateFilters(engine, hostiles, wfpFound);
            Log(LOG_ALERT, "Remediated %d/%d", removed, wfpFound);
            ProtectAllDiscoveredEDRs(engine);
        }

        if ((cycles * MONITOR_INTERVAL_MS) % QOS_CHECK_INTERVAL_MS == 0) {
            char qosNames[128][256];
            int qosFound = QosScanHostilePolicies(qosNames, 128);
            if (qosFound > 0) {
                Log(LOG_ALERT, "=== %d HOSTILE QoS POLICIES ===", qosFound);
                QosRemediatePolicies(qosNames, qosFound);
            }
        }

        Sleep(MONITOR_INTERVAL_MS);
    }

    CloseHandle(stopEvent);
    WfpEngineClose(engine);
    Log(LOG_INFO, "Monitor stopped");
}

int wmain(int argc, wchar_t *argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    const wchar_t *cmd = argv[1];

    if (_wcsicmp(cmd, L"service") == 0) {
        SERVICE_TABLE_ENTRYW table[] = {
            { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
            { NULL, NULL }
        };
        StartServiceCtrlDispatcherW(table);
        return 0;
    }

    if (!IsElevated()) {
        printf("[!] Administrator privileges required.\n");
        printf("    Right-click -> Run as administrator\n");
        return 1;
    }

    LogInit();

    if (_wcsicmp(cmd, L"install") == 0) {
        PrintBanner();
        ServiceInstall();
    }
    else if (_wcsicmp(cmd, L"uninstall") == 0) {
        PrintBanner();
        ServiceUninstall();
    }
    else if (_wcsicmp(cmd, L"start") == 0) {
        PrintBanner();
        CmdStart();
    }
    else if (_wcsicmp(cmd, L"stop") == 0) {
        PrintBanner();
        CmdStop();
    }
    else if (_wcsicmp(cmd, L"monitor") == 0) {
        PrintBanner();
        CmdMonitor();
    }
    else if (_wcsicmp(cmd, L"scan") == 0) {
        PrintBanner();
        CmdScan();
    }
    else if (_wcsicmp(cmd, L"protect") == 0) {
        PrintBanner();
        HANDLE engine = NULL;
        if (WfpEngineOpen(&engine) == ERROR_SUCCESS) {
            WfpRegisterProvider(engine);
            WfpRegisterSublayer(engine);
            int count = ProtectAllDiscoveredEDRs(engine);
            printf("  Protected with %d PERMIT filters.\n\n", count);
            WfpEngineClose(engine);
        }
    }
    else if (_wcsicmp(cmd, L"status") == 0) {
        CmdStatus();
    }
    else if (_wcsicmp(cmd, L"version") == 0) {
        PrintBanner();
    }
    else if (_wcsicmp(cmd, L"help") == 0 || _wcsicmp(cmd, L"--help") == 0
             || _wcsicmp(cmd, L"-h") == 0 || _wcsicmp(cmd, L"/?") == 0) {
        PrintUsage();
    }
    else {
        PrintUsage();
        LogClose();
        return 1;
    }

    LogClose();
    return 0;
}
