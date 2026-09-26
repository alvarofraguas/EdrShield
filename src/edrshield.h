/*
 * EdrShield - WFP/QoS Tamper Protection (Community Edition)
 * Protects Windows Defender / MDE from WFP silencing attacks
 *
 * MIT License
 */

#ifndef EDRSHIELD_H
#define EDRSHIELD_H

#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h>
#include "wfp_compat.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sddl.h>
#include <winsvc.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

/* ═══════════════════════════════════════════
 * Build configuration
 * ═══════════════════════════════════════════ */

#define EDRSHIELD_VERSION       "1.1.0"
#define MONITOR_INTERVAL_MS     1000
#define QOS_CHECK_INTERVAL_MS   5000
#define MAX_FILTERS_ENUM        8192
#define MAX_EDR_PROCESSES       128

/* Service identity */
#define SERVICE_NAME            L"EdrShieldSvc"
#define SERVICE_DISPLAY_NAME    L"EDR Shield Service"
#define SERVICE_DESCRIPTION_STR L"Protects endpoint detection agents from WFP and QoS tampering"

/* Log */
#define LOG_FILE                "C:\\ProgramData\\EdrShield\\edrshield.log"
#define LOG_DIR                 "C:\\ProgramData\\EdrShield"

/* Windows Event Log source */
#define EVENT_SOURCE            "EdrShieldSvc"

/* Event IDs */
#define EVT_MONITOR_STARTED          2001
#define EVT_HOSTILE_WFP_DETECTED     2002
#define EVT_HOSTILE_WFP_REMOVED      2003
#define EVT_HOSTILE_QOS_DETECTED     2004
#define EVT_HOSTILE_QOS_REMOVED      2005
#define EVT_PROTECTIVE_FILTER_ADDED  2006
#define EVT_REMOVAL_FAILED           2007
#define EVT_EDR_CONTAINMENT_DETECTED 2011
#define EVT_TRUSTED_PROVIDER_FOUND   2012

/* ═══════════════════════════════════════════
 * GUIDs (unique to community edition)
 * ═══════════════════════════════════════════ */

/* {A1B2C3D4-E5F6-7890-AB12-CD34EF567890} */
static const GUID EDRSHIELD_SUBLAYER_GUID = {
    0xA1B2C3D4, 0xE5F6, 0x7890,
    {0xAB, 0x12, 0xCD, 0x34, 0xEF, 0x56, 0x78, 0x90}
};

/* {D4C3B2A1-F6E5-0987-21BA-43DC65FE0987} */
static const GUID EDRSHIELD_PROVIDER_GUID = {
    0xD4C3B2A1, 0xF6E5, 0x0987,
    {0x21, 0xBA, 0x43, 0xDC, 0x65, 0xFE, 0x09, 0x87}
};

/* ═══════════════════════════════════════════
 * Known EDR process names (Defender only)
 * ═══════════════════════════════════════════ */

typedef struct {
    const char *exe_name;
    const char *vendor;
} EDR_ENTRY;

static const EDR_ENTRY g_edrList[] = {
    /* Microsoft Defender / MDE */
    { "MsSense.exe",                 "Microsoft" },
    { "MsMpEng.exe",                 "Microsoft" },
    { "SenseIR.exe",                 "Microsoft" },
    { "SenseCncProxy.exe",           "Microsoft" },
    { "SenseNdr.exe",                "Microsoft" },

    /* Terminator */
    { NULL, NULL }
};

/* ═══════════════════════════════════════════
 * Known EDR WFP provider name patterns
 *
 * EDRs use WFP for legitimate containment.
 * We must NEVER remove filters from known providers.
 * Only filters from unknown/hostile providers that
 * BLOCK traffic for known EDR processes are removed.
 * ═══════════════════════════════════════════ */

typedef struct {
    const wchar_t *pattern;
    const char    *vendor;
} EDR_WFP_PATTERN;

/* Filter name patterns */
static const EDR_WFP_PATTERN g_trustedFilterNames[] = {
    { L"Microsoft Defender",         "Microsoft" },
    { L"Windows Defender",           "Microsoft" },
    { L"MpFilter",                   "Microsoft" },
    { L"WFP Lightweight Filter",     "Microsoft" },
    { L"EdrShield",                  "EdrShield" },
    { NULL, NULL }
};

/* Provider name patterns */
static const EDR_WFP_PATTERN g_trustedProviderNames[] = {
    { L"Microsoft Corporation",      "Microsoft" },
    { L"Microsoft Windows",          "Microsoft" },
    { L"EDR Shield",                 "EdrShield" },
    { NULL, NULL }
};

/* Provider install path patterns */
static const EDR_WFP_PATTERN g_trustedProviderPaths[] = {
    { L"\\Windows Defender\\",       "Microsoft" },
    { L"\\Microsoft Defender\\",     "Microsoft" },
    { L"\\EdrShield\\",              "EdrShield" },
    { NULL, NULL }
};

#define MAX_TRUSTED_PROVIDERS 256

/* ═══════════════════════════════════════════
 * Structures
 * ═══════════════════════════════════════════ */

typedef struct {
    UINT64  filterId;
    GUID    filterKey;
    GUID    providerKey;
    char    vendor[64];
    char    providerInfo[128];
    WCHAR   filterName[256];
    WCHAR   appPath[MAX_PATH];
    GUID    layerKey;
} HOSTILE_FILTER;

typedef struct {
    WCHAR   fullPath[MAX_PATH];
    char    exeName[MAX_PATH];
    char    vendor[64];
    DWORD   pid;
} DISCOVERED_EDR;

/* ═══════════════════════════════════════════
 * Logging (log.c)
 * ═══════════════════════════════════════════ */

typedef enum {
    LOG_INFO  = 0,
    LOG_WARN  = 1,
    LOG_ALERT = 2,
    LOG_ERROR = 3
} LogLevel;

void LogInit(void);
void LogClose(void);
void Log(LogLevel level, const char *fmt, ...);
void LogW(LogLevel level, const char *prefix, const wchar_t *wstr);
void WriteEventLog(WORD eventType, DWORD eventId, const char *message);

/* ═══════════════════════════════════════════
 * WFP Engine (wfp.c)
 * ═══════════════════════════════════════════ */

DWORD WfpEngineOpen(HANDLE *engine);
void  WfpEngineClose(HANDLE engine);
DWORD WfpRegisterProvider(HANDLE engine);
DWORD WfpRegisterSublayer(HANDLE engine);

int   WfpScanHostileFilters(HANDLE engine, HOSTILE_FILTER *results, int maxResults);
int   WfpRemediateFilters(HANDLE engine, HOSTILE_FILTER *hostiles, int count);
int   WfpProtectProcess(HANDLE engine, const WCHAR *processPath, const char *vendor);
BOOL  WfpIsOurFilter(const FWPM_FILTER0 *filter);

void  WfpDiscoverTrustedProviders(HANDLE engine);
BOOL  WfpIsFilterTrusted(HANDLE engine, const FWPM_FILTER0 *filter);
int   WfpGetTrustedProviderCount(void);

/* ═══════════════════════════════════════════
 * QoS Defense (qos.c)
 * ═══════════════════════════════════════════ */

int  QosScanHostilePolicies(char hostileNames[][256], int maxResults);
int  QosRemediatePolicies(char hostileNames[][256], int count);

/* ═══════════════════════════════════════════
 * EDR Discovery (discovery.c)
 * ═══════════════════════════════════════════ */

int  DiscoverRunningEDRs(DISCOVERED_EDR *results, int maxResults);
int  ProtectAllDiscoveredEDRs(HANDLE engine);

/* ═══════════════════════════════════════════
 * Service (service.c)
 * ═══════════════════════════════════════════ */

void  ServiceMain(DWORD argc, LPWSTR *argv);
void  ServiceInstall(void);
void  ServiceUninstall(void);
DWORD ServiceCtrlHandler(DWORD control, DWORD eventType,
                         LPVOID eventData, LPVOID context);

/* ═══════════════════════════════════════════
 * Utility
 * ═══════════════════════════════════════════ */

BOOL IsElevated(void);

#endif /* EDRSHIELD_H */
