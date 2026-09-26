/*
 * EdrShield - WFP Engine module (Community Edition)
 *
 * Never remove a WFP filter created by a known EDR provider.
 * Only remove filters from unknown providers that BLOCK
 * traffic for known EDR processes.
 */

#define WFP_MINGW_DEFINE_GUIDS
#include "edrshield.h"

static GUID  g_trustedGuids[MAX_TRUSTED_PROVIDERS];
static char  g_trustedVendors[MAX_TRUSTED_PROVIDERS][64];
static int   g_trustedCount = 0;
static CRITICAL_SECTION g_trustLock;
static BOOL  g_trustInitialized = FALSE;

static void TrustInit(void) {
    if (!g_trustInitialized) {
        InitializeCriticalSection(&g_trustLock);
        g_trustInitialized = TRUE;
    }
}

static BOOL AddTrustedProvider(const GUID *guid, const char *vendor) {
    EnterCriticalSection(&g_trustLock);

    for (int i = 0; i < g_trustedCount; i++) {
        if (memcmp(&g_trustedGuids[i], guid, sizeof(GUID)) == 0) {
            LeaveCriticalSection(&g_trustLock);
            return FALSE;
        }
    }

    if (g_trustedCount < MAX_TRUSTED_PROVIDERS) {
        g_trustedGuids[g_trustedCount] = *guid;
        strncpy(g_trustedVendors[g_trustedCount], vendor, 63);
        g_trustedCount++;
        LeaveCriticalSection(&g_trustLock);
        return TRUE;
    }

    LeaveCriticalSection(&g_trustLock);
    return FALSE;
}

static const char* IsTrustedProviderGuid(const GUID *guid) {
    EnterCriticalSection(&g_trustLock);
    for (int i = 0; i < g_trustedCount; i++) {
        if (memcmp(&g_trustedGuids[i], guid, sizeof(GUID)) == 0) {
            const char *v = g_trustedVendors[i];
            LeaveCriticalSection(&g_trustLock);
            return v;
        }
    }
    LeaveCriticalSection(&g_trustLock);
    return NULL;
}

int WfpGetTrustedProviderCount(void) {
    return g_trustedCount;
}

static BOOL MatchesPattern(const WCHAR *text, const EDR_WFP_PATTERN *patterns) {
    if (!text) return FALSE;

    WCHAR lower[512];
    wcsncpy(lower, text, 511);
    lower[511] = L'\0';
    _wcslwr(lower);

    for (int i = 0; patterns[i].pattern != NULL; i++) {
        WCHAR lowerPat[256];
        wcsncpy(lowerPat, patterns[i].pattern, 255);
        lowerPat[255] = L'\0';
        _wcslwr(lowerPat);

        if (wcsstr(lower, lowerPat) != NULL)
            return TRUE;
    }
    return FALSE;
}

static const char* MatchesPatternVendor(const WCHAR *text, const EDR_WFP_PATTERN *patterns) {
    if (!text) return NULL;

    WCHAR lower[512];
    wcsncpy(lower, text, 511);
    lower[511] = L'\0';
    _wcslwr(lower);

    for (int i = 0; patterns[i].pattern != NULL; i++) {
        WCHAR lowerPat[256];
        wcsncpy(lowerPat, patterns[i].pattern, 255);
        lowerPat[255] = L'\0';
        _wcslwr(lowerPat);

        if (wcsstr(lower, lowerPat) != NULL)
            return patterns[i].vendor;
    }
    return NULL;
}

void WfpDiscoverTrustedProviders(HANDLE engine) {
    TrustInit();

    Log(LOG_INFO, "Discovering trusted WFP providers...");

    AddTrustedProvider(&EDRSHIELD_PROVIDER_GUID, "EdrShield");

    HANDLE enumHandle = NULL;
    DWORD r = FwpmProviderCreateEnumHandle0(engine, NULL, &enumHandle);
    if (r != ERROR_SUCCESS) {
        Log(LOG_ERROR, "Cannot enumerate WFP providers: 0x%08X", r);
        return;
    }

    FWPM_PROVIDER0 **providers = NULL;
    UINT32 numProviders = 0;

    r = FwpmProviderEnum0(engine, enumHandle, 512, &providers, &numProviders);
    if (r == ERROR_SUCCESS && providers) {
        for (UINT32 i = 0; i < numProviders; i++) {
            FWPM_PROVIDER0 *prov = providers[i];
            const char *vendor = NULL;

            if (prov->displayData.name) {
                vendor = MatchesPatternVendor(
                    prov->displayData.name, g_trustedProviderNames);
            }

            if (!vendor && prov->displayData.description) {
                vendor = MatchesPatternVendor(
                    prov->displayData.description, g_trustedProviderNames);
            }

            if (!vendor && prov->serviceName) {
                WCHAR regPath[512];
                swprintf(regPath, 512,
                    L"SYSTEM\\CurrentControlSet\\Services\\%ls",
                    prov->serviceName);

                HKEY hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0,
                                  KEY_READ, &hKey) == ERROR_SUCCESS) {
                    WCHAR imagePath[MAX_PATH] = {0};
                    DWORD pathSize = sizeof(imagePath);
                    DWORD type = 0;

                    if (RegQueryValueExW(hKey, L"ImagePath", NULL, &type,
                                         (LPBYTE)imagePath, &pathSize) == ERROR_SUCCESS) {
                        vendor = MatchesPatternVendor(
                            imagePath, g_trustedProviderPaths);
                    }
                    RegCloseKey(hKey);
                }
            }

            if (vendor) {
                if (AddTrustedProvider(&prov->providerKey, vendor)) {
                    char msg[256];
                    snprintf(msg, sizeof(msg),
                        "Trusted WFP provider discovered: %s (provider: %ls)",
                        vendor,
                        prov->displayData.name ? prov->displayData.name : L"<unnamed>");
                    Log(LOG_INFO, "%s", msg);
                    WriteEventLog(EVENTLOG_INFORMATION_TYPE,
                                  EVT_TRUSTED_PROVIDER_FOUND, msg);
                }
            }
        }
        FwpmFreeMemory0((void **)&providers);
    }

    FwpmProviderDestroyEnumHandle0(engine, enumHandle);

    Log(LOG_INFO, "Trusted provider discovery complete: %d providers cached",
        g_trustedCount);
}

BOOL WfpIsFilterTrusted(HANDLE engine, const FWPM_FILTER0 *filter) {
    if (WfpIsOurFilter(filter))
        return TRUE;

    if (filter->displayData.name) {
        if (MatchesPattern(filter->displayData.name, g_trustedFilterNames))
            return TRUE;
    }

    if (filter->providerKey) {
        const char *vendor = IsTrustedProviderGuid(filter->providerKey);
        if (vendor)
            return TRUE;
    }

    if (filter->providerKey) {
        FWPM_PROVIDER0 *prov = NULL;
        DWORD r = FwpmProviderGetByKey0(engine, filter->providerKey, &prov);
        if (r == ERROR_SUCCESS && prov) {
            BOOL trusted = FALSE;

            if (prov->displayData.name) {
                const char *vendor = MatchesPatternVendor(
                    prov->displayData.name, g_trustedProviderNames);
                if (vendor) {
                    AddTrustedProvider(filter->providerKey, vendor);
                    trusted = TRUE;
                }
            }

            FwpmFreeMemory0((void **)&prov);
            if (trusted) return TRUE;
        }
    }

    return FALSE;
}

DWORD WfpEngineOpen(HANDLE *engine) {
    FWPM_SESSION0 session = {0};
    session.flags = 0;
    session.displayData.name = L"EdrShield Session";
    session.displayData.description = L"EDR Shield WFP Monitor";

    DWORD r = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, engine);
    if (r != ERROR_SUCCESS)
        Log(LOG_ERROR, "FwpmEngineOpen0 failed: 0x%08X", r);
    return r;
}

void WfpEngineClose(HANDLE engine) {
    if (engine) FwpmEngineClose0(engine);
}

DWORD WfpRegisterProvider(HANDLE engine) {
    FWPM_PROVIDER0 prov = {0};
    prov.providerKey = EDRSHIELD_PROVIDER_GUID;
    prov.displayData.name = L"EDR Shield Provider";
    prov.displayData.description = L"EDR Shield - filter health provider";
    prov.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

    DWORD r = FwpmProviderAdd0(engine, &prov, NULL);
    if (r == FWP_E_ALREADY_EXISTS) return ERROR_SUCCESS;
    return r;
}

DWORD WfpRegisterSublayer(HANDLE engine) {
    FWPM_SUBLAYER0 sub = {0};
    sub.subLayerKey = EDRSHIELD_SUBLAYER_GUID;
    sub.displayData.name = L"EDR Shield Sublayer";
    sub.displayData.description = L"Filter health protection sublayer";
    sub.flags = 0;
    sub.weight = 0xFFFF;

    DWORD r = FwpmSubLayerAdd0(engine, &sub, NULL);
    if (r == FWP_E_ALREADY_EXISTS) return ERROR_SUCCESS;
    return r;
}

BOOL WfpIsOurFilter(const FWPM_FILTER0 *filter) {
    return memcmp(&filter->subLayerKey, &EDRSHIELD_SUBLAYER_GUID, sizeof(GUID)) == 0;
}

static BOOL ExtractAppPath(const FWPM_FILTER0 *filter, WCHAR *outPath, int maxChars) {
    for (UINT32 i = 0; i < filter->numFilterConditions; i++) {
        FWPM_FILTER_CONDITION0 *c = &filter->filterCondition[i];
        if (memcmp(&c->fieldKey, &FWPM_CONDITION_ALE_APP_ID, sizeof(GUID)) != 0)
            continue;
        if (c->conditionValue.type != FWP_BYTE_BLOB_TYPE)
            continue;

        FWP_BYTE_BLOB *blob = c->conditionValue.byteBlob;
        if (!blob || !blob->data || blob->size == 0)
            continue;

        int chars = blob->size / sizeof(WCHAR);
        if (chars >= maxChars) chars = maxChars - 1;
        memcpy(outPath, blob->data, chars * sizeof(WCHAR));
        outPath[chars] = L'\0';
        return TRUE;
    }
    return FALSE;
}

static const char* MatchesEDR(const WCHAR *appPath) {
    WCHAR lower[MAX_PATH];
    wcsncpy(lower, appPath, MAX_PATH - 1);
    lower[MAX_PATH - 1] = L'\0';
    _wcslwr(lower);

    for (int i = 0; g_edrList[i].exe_name != NULL; i++) {
        WCHAR wExe[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, g_edrList[i].exe_name, -1, wExe, MAX_PATH);
        _wcslwr(wExe);

        if (wcsstr(lower, wExe) != NULL)
            return g_edrList[i].vendor;
    }
    return NULL;
}

static void GetProviderInfo(HANDLE engine, const GUID *provKey,
                            char *out, int maxLen) {
    if (!provKey) {
        strncpy(out, "<no provider>", maxLen - 1);
        return;
    }

    FWPM_PROVIDER0 *prov = NULL;
    DWORD r = FwpmProviderGetByKey0(engine, provKey, &prov);
    if (r == ERROR_SUCCESS && prov && prov->displayData.name) {
        snprintf(out, maxLen, "%ls", prov->displayData.name);
        FwpmFreeMemory0((void **)&prov);
    } else {
        snprintf(out, maxLen,
            "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            provKey->Data1, provKey->Data2, provKey->Data3,
            provKey->Data4[0], provKey->Data4[1],
            provKey->Data4[2], provKey->Data4[3],
            provKey->Data4[4], provKey->Data4[5],
            provKey->Data4[6], provKey->Data4[7]);
    }
}

int WfpScanHostileFilters(HANDLE engine, HOSTILE_FILTER *results, int maxResults) {
    int found = 0;

    const GUID *layers[] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        &FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        &FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        &FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        NULL
    };

    for (int l = 0; layers[l] != NULL && found < maxResults; l++) {
        HANDLE enumHandle = NULL;
        FWPM_FILTER_ENUM_TEMPLATE0 tmpl = {0};
        tmpl.layerKey = *layers[l];
        tmpl.actionMask = 0xFFFFFFFF;

        DWORD r = FwpmFilterCreateEnumHandle0(engine, &tmpl, &enumHandle);
        if (r != ERROR_SUCCESS) continue;

        FWPM_FILTER0 **filters = NULL;
        UINT32 numFilters = 0;

        r = FwpmFilterEnum0(engine, enumHandle, MAX_FILTERS_ENUM,
                            &filters, &numFilters);

        if (r == ERROR_SUCCESS && filters) {
            for (UINT32 i = 0; i < numFilters && found < maxResults; i++) {
                FWPM_FILTER0 *f = filters[i];

                if (f->action.type != FWP_ACTION_BLOCK &&
                    f->action.type != FWP_ACTION_CALLOUT_TERMINATING)
                    continue;

                WCHAR appPath[MAX_PATH] = {0};
                if (!ExtractAppPath(f, appPath, MAX_PATH))
                    continue;

                const char *targetVendor = MatchesEDR(appPath);
                if (!targetVendor) continue;

                if (WfpIsFilterTrusted(engine, f)) {
                    Log(LOG_INFO,
                        "EDR containment filter detected (SAFE): "
                        "target=%s name='%ls' — NOT removing",
                        targetVendor,
                        f->displayData.name ? f->displayData.name : L"<unnamed>");

                    char msg[512];
                    snprintf(msg, sizeof(msg),
                        "EDR containment filter detected (legitimate): "
                        "target=%s filter=%ls — no action taken",
                        targetVendor,
                        f->displayData.name ? f->displayData.name : L"<unnamed>");
                    WriteEventLog(EVENTLOG_INFORMATION_TYPE,
                                  EVT_EDR_CONTAINMENT_DETECTED, msg);
                    continue;
                }

                results[found].filterId = f->filterId;
                results[found].filterKey = f->filterKey;
                results[found].layerKey = f->layerKey;
                strncpy(results[found].vendor, targetVendor, 63);
                wcsncpy(results[found].appPath, appPath, MAX_PATH - 1);

                if (f->providerKey)
                    results[found].providerKey = *f->providerKey;
                else
                    memset(&results[found].providerKey, 0, sizeof(GUID));

                if (f->displayData.name)
                    wcsncpy(results[found].filterName,
                            f->displayData.name, 255);
                else
                    wcscpy(results[found].filterName, L"<unnamed>");

                GetProviderInfo(engine, f->providerKey,
                                results[found].providerInfo, 128);

                found++;
            }
            FwpmFreeMemory0((void **)&filters);
        }

        FwpmFilterDestroyEnumHandle0(engine, enumHandle);
    }

    return found;
}

int WfpRemediateFilters(HANDLE engine, HOSTILE_FILTER *hostiles, int count) {
    int removed = 0;
    char msg[512];

    for (int i = 0; i < count; i++) {
        FWPM_FILTER0 *liveFilter = NULL;
        DWORD fetchResult = FwpmFilterGetById0(engine, hostiles[i].filterId, &liveFilter);
        if (fetchResult == ERROR_SUCCESS && liveFilter) {
            if (WfpIsFilterTrusted(engine, liveFilter)) {
                Log(LOG_WARN,
                    "SKIPPING filter id=%llu — became trusted between scan and remediate",
                    (unsigned long long)hostiles[i].filterId);
                FwpmFreeMemory0((void **)&liveFilter);
                continue;
            }
            FwpmFreeMemory0((void **)&liveFilter);
        } else if (fetchResult != ERROR_SUCCESS &&
                   fetchResult != FWP_E_FILTER_NOT_FOUND) {
            const char *trustedVendor = IsTrustedProviderGuid(&hostiles[i].providerKey);
            if (trustedVendor) {
                Log(LOG_WARN,
                    "SKIPPING filter id=%llu — provider trusted (%s), re-fetch failed",
                    (unsigned long long)hostiles[i].filterId, trustedVendor);
                continue;
            }
        }

        snprintf(msg, sizeof(msg),
            "HOSTILE WFP filter: target=%s filterId=%llu provider=%s name=%ls",
            hostiles[i].vendor,
            (unsigned long long)hostiles[i].filterId,
            hostiles[i].providerInfo,
            hostiles[i].filterName);
        WriteEventLog(EVENTLOG_WARNING_TYPE, EVT_HOSTILE_WFP_DETECTED, msg);

        Log(LOG_ALERT, "HOSTILE FILTER: id=%llu target=%s provider=%s name='%ls'",
            (unsigned long long)hostiles[i].filterId,
            hostiles[i].vendor,
            hostiles[i].providerInfo,
            hostiles[i].filterName);

        DWORD r = FwpmFilterDeleteById0(engine, hostiles[i].filterId);
        if (r == ERROR_SUCCESS) {
            Log(LOG_ALERT, "REMOVED filter id=%llu (target: %s)",
                (unsigned long long)hostiles[i].filterId, hostiles[i].vendor);

            snprintf(msg, sizeof(msg),
                "Hostile WFP filter REMOVED: target=%s filterId=%llu provider=%s",
                hostiles[i].vendor,
                (unsigned long long)hostiles[i].filterId,
                hostiles[i].providerInfo);
            WriteEventLog(EVENTLOG_INFORMATION_TYPE, EVT_HOSTILE_WFP_REMOVED, msg);
            removed++;
        } else {
            r = FwpmFilterDeleteByKey0(engine, &hostiles[i].filterKey);
            if (r == ERROR_SUCCESS) {
                removed++;
            } else {
                Log(LOG_ERROR, "FAILED to remove filter id=%llu: 0x%08X",
                    (unsigned long long)hostiles[i].filterId, r);

                snprintf(msg, sizeof(msg),
                    "FAILED to remove hostile filter: target=%s err=0x%08X",
                    hostiles[i].vendor, r);
                WriteEventLog(EVENTLOG_ERROR_TYPE, EVT_REMOVAL_FAILED, msg);
            }
        }
    }

    return removed;
}

int WfpProtectProcess(HANDLE engine, const WCHAR *processPath, const char *vendor) {
    int added = 0;
    FWP_BYTE_BLOB *appId = NULL;
    char msg[512];

    DWORD r = FwpmGetAppIdFromFileName0(processPath, &appId);
    if (r != ERROR_SUCCESS) return 0;

    const GUID *layers[] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        &FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        NULL
    };

    UINT64 maxWeight = 0xFFFFFFFFFFFFFFFF;

    for (int i = 0; layers[i] != NULL; i++) {
        FWPM_FILTER_CONDITION0 cond = {0};
        cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        cond.conditionValue.byteBlob = appId;

        FWPM_FILTER0 filter = {0};
        filter.displayData.name = L"EdrShield Health Filter";
        filter.displayData.description = L"EDR Shield - process connectivity health";
        filter.layerKey = *layers[i];
        filter.subLayerKey = EDRSHIELD_SUBLAYER_GUID;
        filter.providerKey = (GUID *)&EDRSHIELD_PROVIDER_GUID;
        filter.action.type = FWP_ACTION_PERMIT;
        filter.weight.type = FWP_UINT64;
        filter.weight.uint64 = &maxWeight;
        filter.numFilterConditions = 1;
        filter.filterCondition = &cond;
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT;

        UINT64 filterId = 0;
        r = FwpmFilterAdd0(engine, &filter, NULL, &filterId);
        if (r == ERROR_SUCCESS || r == FWP_E_ALREADY_EXISTS)
            added++;
    }

    FwpmFreeMemory0((void **)&appId);

    if (added > 0) {
        snprintf(msg, sizeof(msg),
            "Protective PERMIT filters: vendor=%s count=%d", vendor, added);
        WriteEventLog(EVENTLOG_INFORMATION_TYPE, EVT_PROTECTIVE_FILTER_ADDED, msg);
    }

    return added;
}
