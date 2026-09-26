/*
 * EdrShield - QoS Defense module (Community Edition)
 * Detects and removes hostile QoS policies that throttle EDR bandwidth
 */

#include "edrshield.h"

int QosScanHostilePolicies(char hostileNames[][256], int maxResults) {
    int found = 0;
    char cmd[1024];
    char line[512];

    const char *tmpFile = "C:\\ProgramData\\EdrShield\\qos_scan.tmp";

    snprintf(cmd, sizeof(cmd),
        "powershell -NoProfile -Command \""
        "Get-NetQosPolicy | Select-Object Name, AppPathNameMatchCondition, "
        "ThrottleRateActionBitsPerSecond | ConvertTo-Csv -NoTypeInformation"
        "\" > \"%s\" 2>nul",
        tmpFile);

    system(cmd);

    FILE *f = fopen(tmpFile, "r");
    if (!f) return 0;

    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        DeleteFileA(tmpFile);
        return 0;
    }

    while (fgets(line, sizeof(line), f) && found < maxResults) {
        char name[256] = {0};
        char appPath[256] = {0};
        char throttle[64] = {0};

        char *p = line;
        char *fields[3] = {NULL, NULL, NULL};
        int fieldIdx = 0;

        while (*p && fieldIdx < 3) {
            if (*p == '"') {
                p++;
                fields[fieldIdx] = p;
                char *end = strchr(p, '"');
                if (end) {
                    *end = '\0';
                    p = end + 1;
                    if (*p == ',') p++;
                }
                fieldIdx++;
            } else {
                fields[fieldIdx] = p;
                char *end = strchr(p, ',');
                if (end) {
                    *end = '\0';
                    p = end + 1;
                } else {
                    char *nl = strchr(p, '\n');
                    if (nl) *nl = '\0';
                    nl = strchr(p, '\r');
                    if (nl) *nl = '\0';
                    p += strlen(p);
                }
                fieldIdx++;
            }
        }

        if (!fields[0] || !fields[1]) continue;

        strncpy(name, fields[0], 255);
        strncpy(appPath, fields[1], 255);
        if (fields[2]) strncpy(throttle, fields[2], 63);

        if (strlen(appPath) == 0) continue;

        char lowerApp[256];
        strncpy(lowerApp, appPath, 255);
        _strlwr(lowerApp);

        for (int i = 0; g_edrList[i].exe_name != NULL; i++) {
            char lowerEdr[256];
            strncpy(lowerEdr, g_edrList[i].exe_name, 255);
            _strlwr(lowerEdr);

            if (strstr(lowerApp, lowerEdr) != NULL) {
                strncpy(hostileNames[found], name, 255);
                found++;

                Log(LOG_ALERT, "HOSTILE QoS POLICY: name='%s' target='%s' throttle=%s bps",
                    name, appPath, throttle[0] ? throttle : "?");

                char msg[512];
                snprintf(msg, sizeof(msg),
                    "Hostile QoS policy detected: name=%s target=%s throttle=%s",
                    name, appPath, throttle);
                WriteEventLog(EVENTLOG_WARNING_TYPE, EVT_HOSTILE_QOS_DETECTED, msg);
                break;
            }
        }
    }

    fclose(f);
    DeleteFileA(tmpFile);
    return found;
}

static BOOL SanitizePolicyName(const char *input, char *output, int maxLen) {
    int j = 0;
    for (int i = 0; input[i] && j < maxLen - 1; i++) {
        char c = input[i];
        if (c == '\'' || c == '`' || c == '$' || c == '"' ||
            c == ';'  || c == '|' || c == '&' || c == '\n' ||
            c == '\r' || c == '\0') {
            return FALSE;
        }
        if (c < 0x20 || c == 0x7F)
            return FALSE;
        output[j++] = c;
    }
    output[j] = '\0';
    return j > 0;
}

int QosRemediatePolicies(char hostileNames[][256], int count) {
    int removed = 0;
    char cmd[1024];

    for (int i = 0; i < count; i++) {
        char safeName[256];
        if (!SanitizePolicyName(hostileNames[i], safeName, sizeof(safeName))) {
            Log(LOG_ERROR, "QoS policy name contains unsafe characters, skipping");
            continue;
        }

        Log(LOG_ALERT, "REMOVING hostile QoS policy: '%s'", safeName);

        snprintf(cmd, sizeof(cmd),
            "powershell -NoProfile -Command \""
            "Remove-NetQosPolicy -Name '%s' -Confirm:$false "
            "-ErrorAction SilentlyContinue"
            "\" >nul 2>&1",
            safeName);

        int ret = system(cmd);
        if (ret == 0) {
            Log(LOG_ALERT, "REMOVED QoS policy: '%s'", safeName);

            char msg[512];
            snprintf(msg, sizeof(msg),
                "Hostile QoS policy REMOVED: name=%s", safeName);
            WriteEventLog(EVENTLOG_INFORMATION_TYPE, EVT_HOSTILE_QOS_REMOVED, msg);
            removed++;
        } else {
            Log(LOG_ERROR, "FAILED to remove QoS policy: '%s'", safeName);
        }
    }

    return removed;
}
