/*
 * EdrShield - EDR Discovery module (Community Edition)
 * Enumerates running Defender processes
 */

#include "edrshield.h"

int DiscoverRunningEDRs(DISCOVERED_EDR *results, int maxResults) {
    int found = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        Log(LOG_ERROR, "CreateToolhelp32Snapshot failed: 0x%08X", GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return 0;
    }

    char seenPaths[MAX_EDR_PROCESSES][MAX_PATH];
    int seenCount = 0;

    do {
        char narrowExe[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1,
                            narrowExe, MAX_PATH, NULL, NULL);

        for (int i = 0; g_edrList[i].exe_name != NULL; i++) {
            if (_stricmp(narrowExe, g_edrList[i].exe_name) != 0)
                continue;

            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) break;

            WCHAR fullPath[MAX_PATH] = {0};
            DWORD pathLen = MAX_PATH;

            if (!QueryFullProcessImageNameW(hProc, 0, fullPath, &pathLen)) {
                CloseHandle(hProc);
                break;
            }
            CloseHandle(hProc);

            char narrowPath[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, fullPath, -1,
                                narrowPath, MAX_PATH, NULL, NULL);
            BOOL dup = FALSE;
            for (int s = 0; s < seenCount; s++) {
                if (_stricmp(seenPaths[s], narrowPath) == 0) {
                    dup = TRUE;
                    break;
                }
            }
            if (dup) break;

            if (seenCount < MAX_EDR_PROCESSES)
                strncpy(seenPaths[seenCount++], narrowPath, MAX_PATH - 1);

            if (found < maxResults) {
                wcsncpy(results[found].fullPath, fullPath, MAX_PATH - 1);
                strncpy(results[found].exeName, g_edrList[i].exe_name, MAX_PATH - 1);
                strncpy(results[found].vendor, g_edrList[i].vendor, 63);
                results[found].pid = pe.th32ProcessID;
                found++;

                Log(LOG_INFO, "Discovered EDR: %s (%s) PID=%lu",
                    g_edrList[i].exe_name, g_edrList[i].vendor,
                    (unsigned long)pe.th32ProcessID);
            }
            break;
        }
    } while (Process32NextW(snap, &pe) && found < maxResults);

    CloseHandle(snap);
    return found;
}

int ProtectAllDiscoveredEDRs(HANDLE engine) {
    DISCOVERED_EDR edrs[MAX_EDR_PROCESSES];
    int count = DiscoverRunningEDRs(edrs, MAX_EDR_PROCESSES);

    int totalFilters = 0;

    for (int i = 0; i < count; i++) {
        int added = WfpProtectProcess(engine, edrs[i].fullPath, edrs[i].vendor);
        if (added > 0) {
            Log(LOG_INFO, "Protected %s (%s): %d PERMIT filters",
                edrs[i].exeName, edrs[i].vendor, added);
            totalFilters += added;
        }
    }

    Log(LOG_INFO, "EDR protection complete: %d EDRs, %d PERMIT filters",
        count, totalFilters);
    return totalFilters;
}
