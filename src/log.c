/*
 * EdrShield - Logging module (Community Edition)
 */

#include "edrshield.h"
#include <stdarg.h>

static FILE *g_logFile = NULL;
static CRITICAL_SECTION g_logLock;

static const char* LevelStr(LogLevel level) {
    switch (level) {
        case LOG_INFO:  return "INFO ";
        case LOG_WARN:  return "WARN ";
        case LOG_ALERT: return "ALERT";
        case LOG_ERROR: return "ERROR";
        default:        return "?????";
    }
}

void LogInit(void) {
    InitializeCriticalSection(&g_logLock);
    CreateDirectoryA(LOG_DIR, NULL);
    g_logFile = fopen(LOG_FILE, "a");
}

void LogClose(void) {
    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = NULL;
    }
    DeleteCriticalSection(&g_logLock);
}

void Log(LogLevel level, const char *fmt, ...) {
    EnterCriticalSection(&g_logLock);

    SYSTEMTIME st;
    GetLocalTime(&st);
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;

    va_start(args, fmt);
    printf("[%s] [%s] ", timestamp, LevelStr(level));
    vprintf(fmt, args);
    printf("\n");
    va_end(args);

    if (g_logFile) {
        va_start(args, fmt);
        fprintf(g_logFile, "[%s] [%s] ", timestamp, LevelStr(level));
        vfprintf(g_logFile, fmt, args);
        fprintf(g_logFile, "\n");
        fflush(g_logFile);
        va_end(args);
    }

    LeaveCriticalSection(&g_logLock);
}

void LogW(LogLevel level, const char *prefix, const wchar_t *wstr) {
    EnterCriticalSection(&g_logLock);

    SYSTEMTIME st;
    GetLocalTime(&st);
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    printf("[%s] [%s] %s: %ls\n", timestamp, LevelStr(level), prefix, wstr);
    if (g_logFile) {
        fprintf(g_logFile, "[%s] [%s] %s: %ls\n",
                timestamp, LevelStr(level), prefix, wstr);
        fflush(g_logFile);
    }

    LeaveCriticalSection(&g_logLock);
}

void WriteEventLog(WORD eventType, DWORD eventId, const char *message) {
    HANDLE hLog = RegisterEventSourceA(NULL, EVENT_SOURCE);
    if (hLog) {
        const char *strings[1] = { message };
        ReportEventA(hLog, eventType, 0, eventId, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hLog);
    }
}
