/*
 * EdrShield - Windows Service module (Community Edition)
 */

#include "edrshield.h"

static SERVICE_STATUS_HANDLE g_statusHandle = NULL;
static SERVICE_STATUS        g_status = {0};
static HANDLE                g_stopEvent = NULL;
static HANDLE                g_wfpEngine = NULL;

static void ReportStatus(DWORD state, DWORD exitCode, DWORD waitHint) {
    static DWORD checkpoint = 0;

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint = waitHint;

    if (state == SERVICE_START_PENDING)
        g_status.dwControlsAccepted = 0;
    else
        g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED)
        g_status.dwCheckPoint = 0;
    else
        g_status.dwCheckPoint = ++checkpoint;

    SetServiceStatus(g_statusHandle, &g_status);
}

DWORD ServiceCtrlHandler(DWORD control, DWORD eventType,
                         LPVOID eventData, LPVOID context) {
    (void)eventType; (void)eventData; (void)context;

    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            Log(LOG_INFO, "Service stop requested");
            ReportStatus(SERVICE_STOP_PENDING, 0, 3000);
            SetEvent(g_stopEvent);
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void MonitorLoop(HANDLE engine, HANDLE stopEvent) {
    int totalWfpRemoved = 0;
    int totalQosRemoved = 0;
    int cycles = 0;

    Log(LOG_INFO, "Monitor active (WFP: %dms, QoS: %dms)",
        MONITOR_INTERVAL_MS, QOS_CHECK_INTERVAL_MS);

    while (WaitForSingleObject(stopEvent, MONITOR_INTERVAL_MS) == WAIT_TIMEOUT) {
        cycles++;

        HOSTILE_FILTER hostiles[512];
        int wfpFound = WfpScanHostileFilters(engine, hostiles, 512);

        if (wfpFound > 0) {
            Log(LOG_ALERT, "=== %d HOSTILE WFP FILTERS DETECTED ===", wfpFound);
            int removed = WfpRemediateFilters(engine, hostiles, wfpFound);
            totalWfpRemoved += removed;
            Log(LOG_ALERT, "Remediated %d/%d WFP filters (total: %d)",
                removed, wfpFound, totalWfpRemoved);
            ProtectAllDiscoveredEDRs(engine);
        }

        if ((cycles * MONITOR_INTERVAL_MS) % QOS_CHECK_INTERVAL_MS == 0) {
            char qosNames[128][256];
            int qosFound = QosScanHostilePolicies(qosNames, 128);

            if (qosFound > 0) {
                Log(LOG_ALERT, "=== %d HOSTILE QoS POLICIES DETECTED ===", qosFound);
                int removed = QosRemediatePolicies(qosNames, qosFound);
                totalQosRemoved += removed;
                Log(LOG_ALERT, "Remediated %d/%d QoS policies (total: %d)",
                    removed, qosFound, totalQosRemoved);
            }
        }
    }

    Log(LOG_INFO, "Monitor stopped. WFP removed: %d, QoS removed: %d",
        totalWfpRemoved, totalQosRemoved);
}

void ServiceMain(DWORD argc, LPWSTR *argv) {
    (void)argc; (void)argv;

    g_statusHandle = RegisterServiceCtrlHandlerExW(
        SERVICE_NAME, (LPHANDLER_FUNCTION_EX)ServiceCtrlHandler, NULL);
    if (!g_statusHandle) return;

    ReportStatus(SERVICE_START_PENDING, 0, 5000);

    g_stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_stopEvent) {
        ReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    LogInit();
    Log(LOG_INFO, "=== EdrShield v%s starting as service ===", EDRSHIELD_VERSION);

    if (WfpEngineOpen(&g_wfpEngine) != ERROR_SUCCESS) {
        Log(LOG_ERROR, "Cannot open WFP engine — aborting");
        ReportStatus(SERVICE_STOPPED, 1, 0);
        return;
    }

    WfpRegisterProvider(g_wfpEngine);
    WfpRegisterSublayer(g_wfpEngine);

    WfpDiscoverTrustedProviders(g_wfpEngine);
    Log(LOG_INFO, "Trusted providers cached: %d", WfpGetTrustedProviderCount());

    int protectedCount = ProtectAllDiscoveredEDRs(g_wfpEngine);
    Log(LOG_INFO, "Initial protection: %d PERMIT filters", protectedCount);

    WriteEventLog(EVENTLOG_INFORMATION_TYPE, EVT_MONITOR_STARTED,
        "EdrShield monitor started: WFP + QoS tamper protection active");

    ReportStatus(SERVICE_RUNNING, 0, 0);

    MonitorLoop(g_wfpEngine, g_stopEvent);

    WfpEngineClose(g_wfpEngine);
    CloseHandle(g_stopEvent);
    LogClose();

    ReportStatus(SERVICE_STOPPED, 0, 0);
}

void ServiceInstall(void) {
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    WCHAR cmdLine[MAX_PATH + 32];
    swprintf(cmdLine, MAX_PATH + 32, L"\"%ls\" service", path);

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) {
        printf("[!] Cannot open SCM (run as admin)\n");
        return;
    }

    SC_HANDLE hSvc = CreateServiceW(
        hScm, SERVICE_NAME, SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        cmdLine, NULL, NULL,
        L"BFE\0RpcSs\0", NULL, NULL
    );

    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            printf("[*] Service already exists.\n");
        else
            printf("[!] CreateService failed: 0x%08X\n", err);
        CloseServiceHandle(hScm);
        return;
    }

    SERVICE_DESCRIPTIONW desc = {0};
    desc.lpDescription = (LPWSTR)SERVICE_DESCRIPTION_STR;
    ChangeServiceConfig2W(hSvc, SERVICE_CONFIG_DESCRIPTION, &desc);

    SERVICE_FAILURE_ACTIONSW failActions = {0};
    failActions.dwResetPeriod = 60;
    failActions.cActions = 3;
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 0 },
        { SC_ACTION_RESTART, 1000 },
        { SC_ACTION_RESTART, 5000 }
    };
    failActions.lpsaActions = actions;
    ChangeServiceConfig2W(hSvc, SERVICE_CONFIG_FAILURE_ACTIONS, &failActions);

    printf("[+] Service installed: %ls\n", SERVICE_NAME);
    printf("[+] Start with: sc start %ls\n", SERVICE_NAME);

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

void ServiceUninstall(void) {
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        printf("[!] Cannot open SCM\n");
        return;
    }

    SC_HANDLE hSvc = OpenServiceW(hScm, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (!hSvc) {
        printf("[!] Cannot open service\n");
        CloseServiceHandle(hScm);
        return;
    }

    SERVICE_STATUS status;
    ControlService(hSvc, SERVICE_CONTROL_STOP, &status);
    Sleep(2000);

    if (DeleteService(hSvc))
        printf("[+] Service removed.\n");
    else
        printf("[!] DeleteService failed: 0x%08X\n", GetLastError());

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

BOOL IsElevated(void) {
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev;
        DWORD size = sizeof(elev);
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size))
            elevated = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated;
}
