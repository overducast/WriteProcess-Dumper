#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "kernel32.lib")


#ifdef _WIN64
  #define FMT_PTR  "0x%llx"
  #define FMT_SIZE "0x%llx"
  #define CAST_PTR(x)  ((unsigned long long)(ULONG_PTR)(x))
  #define CAST_SIZE(x) ((unsigned long long)(x))
#else
  #define FMT_PTR  "0x%lx"
  #define FMT_SIZE "0x%lx"
  #define CAST_PTR(x)  ((unsigned long)(ULONG_PTR)(x))
  #define CAST_SIZE(x) ((unsigned long)(x))
#endif
/*
   x86 patch = 5 bytes  (E9 rel32)
   x64 patch = 14 bytes (FF25 00000000 + 8-byte abs addr)
*/
struct HookCtx
{
    BYTE*            pTarget;
    BYTE             origBytes[16];
    BYTE             jmpBytes[16];
    DWORD            patchLen;
    CRITICAL_SECTION cs;
    BOOL             active;
};

static BOOL InstallHook(HookCtx* h, void* pTarget, void* pDetour)
{
    ZeroMemory(h, sizeof(*h));
    h->pTarget = (BYTE*)pTarget;
    InitializeCriticalSection(&h->cs);

#ifdef _WIN64
    h->patchLen    = 14;
    h->jmpBytes[0] = 0xFF;
    h->jmpBytes[1] = 0x25;
    *(DWORD*) &h->jmpBytes[2] = 0x00000000;
    *(UINT64*)&h->jmpBytes[6] = (UINT64)pDetour;
#else
    h->patchLen    = 5;
    h->jmpBytes[0] = 0xE9;
    *(DWORD*)&h->jmpBytes[1] = (DWORD)((BYTE*)pDetour - h->pTarget - 5);
#endif

    DWORD oldProt;
    if (!VirtualProtect(h->pTarget, h->patchLen, PAGE_EXECUTE_READWRITE, &oldProt))
        return FALSE;

    memcpy(h->origBytes, h->pTarget,   h->patchLen);
    memcpy(h->pTarget,   h->jmpBytes,  h->patchLen);

    VirtualProtect(h->pTarget, h->patchLen, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), h->pTarget, h->patchLen);

    h->active = TRUE;
    return TRUE;
}

static void RemoveHook(HookCtx* h)
{
    if (!h->active) return;
    DWORD oldProt;
    VirtualProtect(h->pTarget, h->patchLen, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(h->pTarget, h->origBytes, h->patchLen);
    VirtualProtect(h->pTarget, h->patchLen, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), h->pTarget, h->patchLen);
    h->active = FALSE;
    DeleteCriticalSection(&h->cs);
}

static void PauseHook(HookCtx* h)
{
    EnterCriticalSection(&h->cs);
    DWORD oldProt;
    VirtualProtect(h->pTarget, h->patchLen, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(h->pTarget, h->origBytes, h->patchLen);
    VirtualProtect(h->pTarget, h->patchLen, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), h->pTarget, h->patchLen);
}

static void UnpauseHook(HookCtx* h)
{
    DWORD oldProt;
    VirtualProtect(h->pTarget, h->patchLen, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(h->pTarget, h->jmpBytes, h->patchLen);
    VirtualProtect(h->pTarget, h->patchLen, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), h->pTarget, h->patchLen);
    LeaveCriticalSection(&h->cs);
}

static HookCtx  g_hookWPM = {};
static HookCtx  g_hookVAE = {};

static HMODULE  g_hThisDll              = NULL;
static char     g_dumpDir[MAX_PATH]     = {};
static char     g_timestamp[64]         = {};
static volatile LONG g_dumpIndex        = 0;

static FILE*            g_logFile = NULL;
static CRITICAL_SECTION g_logCS   = {};

struct AllocRecord {
    ULONG_PTR base;
    SIZE_T    size;
    DWORD     protect;
};

#define MAX_ALLOC_RECORDS 4096
static AllocRecord      g_allocs[MAX_ALLOC_RECORDS] = {};
static LONG             g_allocCount                = 0;   
static CRITICAL_SECTION g_allocCS                   = {};

static void Log(const char* fmt, ...)
{
    EnterCriticalSection(&g_logCS);

    va_list ap;

    if (g_logFile) {
        va_start(ap, fmt);
        vfprintf(g_logFile, fmt, ap);
        va_end(ap);
        fflush(g_logFile);
    }

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    LeaveCriticalSection(&g_logCS);
}

static BOOL IsProtectExecutable(DWORD prot)
{
    return (prot & (PAGE_EXECUTE |
                    PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE |
                    PAGE_EXECUTE_WRITECOPY)) != 0;
}

static BOOL IsTrackedExecRegion(ULONG_PTR addr)
{
    EnterCriticalSection(&g_allocCS);
    for (LONG i = 0; i < g_allocCount; i++) {
        ULONG_PTR base = g_allocs[i].base;
        ULONG_PTR end  = base + g_allocs[i].size;
        if (addr >= base && addr < end && IsProtectExecutable(g_allocs[i].protect)) {
            LeaveCriticalSection(&g_allocCS);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_allocCS);
    return FALSE;
}

static BOOL IsMZHeader(LPCVOID buf, SIZE_T size)
{
    if (size >= 2) {
        const BYTE* p = (const BYTE*)buf;
        return (p[0] == 'M' && p[1] == 'Z');
    }
    return FALSE;
}

static const char* ProtectStr(DWORD prot)
{
    switch (prot & 0xFF) {
    case PAGE_NOACCESS:          return "PAGE_NOACCESS";
    case PAGE_READONLY:          return "PAGE_READONLY";
    case PAGE_READWRITE:         return "PAGE_READWRITE";
    case PAGE_WRITECOPY:         return "PAGE_WRITECOPY";
    case PAGE_EXECUTE:           return "PAGE_EXECUTE";
    case PAGE_EXECUTE_READ:      return "PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
    default:                     return "UNKNOWN";
    }
}

static LPVOID WINAPI Hooked_VirtualAllocEx(
    HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
    DWORD  flAllocationType, DWORD flProtect)
{
    PauseHook(&g_hookVAE);
    LPVOID result = VirtualAllocEx(hProcess, lpAddress, dwSize,
                                   flAllocationType, flProtect);
    UnpauseHook(&g_hookVAE);

    Log("VirtualAllocEx(" FMT_PTR ", " FMT_PTR ", " FMT_SIZE
        ", 0x%lx, 0x%lx [%s]) => " FMT_PTR "\n",
        CAST_PTR(hProcess), CAST_PTR(lpAddress), CAST_SIZE(dwSize),
        flAllocationType, flProtect, ProtectStr(flProtect),
        CAST_PTR(result));

    /* Track the new region so WriteProcessMemory can detect EXEC writes. */
    if (result) {
        EnterCriticalSection(&g_allocCS);
        if (g_allocCount < MAX_ALLOC_RECORDS) {
            g_allocs[g_allocCount].base    = (ULONG_PTR)result;
            g_allocs[g_allocCount].size    = dwSize;
            g_allocs[g_allocCount].protect = flProtect;
            g_allocCount++;
        } else {
            Log("  WARNING: alloc tracking table full (%d entries) — EXEC detection may miss regions\n",
                MAX_ALLOC_RECORDS);
        }
        LeaveCriticalSection(&g_allocCS);
    }

    return result;
}

static BOOL WINAPI Hooked_WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten)
{
    const char* suffix = "";
    BOOL isMZ   = IsMZHeader(lpBuffer, nSize);
    BOOL isExec = IsTrackedExecRegion((ULONG_PTR)lpBaseAddress);

    MEMORY_BASIC_INFORMATION mbi = {};
    BOOL hasRemoteInfo = (VirtualQueryEx(hProcess, lpBaseAddress,
                                         &mbi, sizeof(mbi)) != 0);

    if (isMZ || isExec || (hasRemoteInfo && IsProtectExecutable(mbi.Protect)))
        suffix = "-EXEC";  

    LONG idx = InterlockedIncrement(&g_dumpIndex) - 1;
    Log("WriteProcessMemory(" FMT_PTR ", " FMT_PTR ", " FMT_PTR
        ", " FMT_SIZE ", " FMT_PTR ")\n",
        CAST_PTR(hProcess), CAST_PTR(lpBaseAddress),
        CAST_PTR(lpBuffer), CAST_SIZE(nSize),
        CAST_PTR(lpNumberOfBytesWritten));

    if (hasRemoteInfo) {
        Log("  Region: base=" FMT_PTR " size=" FMT_SIZE
            " protect=0x%lx [%s] state=0x%lx type=0x%lx\n",
            CAST_PTR(mbi.BaseAddress), CAST_SIZE(mbi.RegionSize),
            mbi.Protect, ProtectStr(mbi.Protect),
            mbi.State, mbi.Type);
    }

    if (isMZ)
        Log("  ** Buffer starts with MZ — PE image header detected\n");
/* Dump buffer */
    char filename[MAX_PATH];
    _snprintf_s(filename, MAX_PATH, _TRUNCATE,
                "%s\\WPMDump-%s-%ld%s.bin",
                g_dumpDir, g_timestamp, (long)idx, suffix);

    FILE* f = NULL;
    fopen_s(&f, filename, "wb");
    if (f) {
        fwrite(lpBuffer, 1, nSize, f);
        fclose(f);
        Log("  Dump: %s\n", filename);
    } else {
        Log("  ERROR: Could not create dump file: %s (err=%lu)\n",
            filename, GetLastError());
    }

    PauseHook(&g_hookWPM);
    BOOL result = WriteProcessMemory(hProcess, lpBaseAddress,
                                     lpBuffer, nSize,
                                     lpNumberOfBytesWritten);
    UnpauseHook(&g_hookWPM);

    return result;
}

/* dll ep */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        g_hThisDll = hModule;

        AllocConsole();
        freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);

        GetModuleFileNameA(hModule, g_dumpDir, MAX_PATH);
        {
            char* slash = strrchr(g_dumpDir, '\\');
            if (slash) *slash = '\0';
        }

        {
            time_t now = time(NULL);
            struct tm t;
            localtime_s(&t, &now);
            sprintf_s(g_timestamp, sizeof(g_timestamp),
                      "%04d-%02d-%02d-%02d-%02d-%02d",
                      t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                      t.tm_hour, t.tm_min, t.tm_sec);
        }

        InitializeCriticalSection(&g_logCS);
        {
            char logPath[MAX_PATH];
            _snprintf_s(logPath, MAX_PATH, _TRUNCATE,
                        "%s\\WPMDump-%s.txt", g_dumpDir, g_timestamp);
            fopen_s(&g_logFile, logPath, "w");
        }

        InitializeCriticalSection(&g_allocCS);

        printf("\n");
        printf("  Dump dir  : %s\n", g_dumpDir);
        printf("  Timestamp : %s\n", g_timestamp);
#ifdef _WIN64
        printf("  Arch      : x64\n");
#else
        printf("  Arch      : x86\n");
#endif

        HMODULE hK32 = GetModuleHandleA("kernel32.dll");
        void* pWPM = (void*)GetProcAddress(hK32, "WriteProcessMemory");
        void* pVAE = (void*)GetProcAddress(hK32, "VirtualAllocEx");

        if (pWPM && InstallHook(&g_hookWPM, pWPM, (void*)Hooked_WriteProcessMemory)) {
            printf("  [ + ] Hooked WriteProcessMemory at " FMT_PTR "\n", CAST_PTR(pWPM));
            Log("[ + ] Hooked WriteProcessMemory at " FMT_PTR "\n", CAST_PTR(pWPM));
        } else {
            printf("  [ - ] FAILED to hook WriteProcessMemory (err=%lu)\n", GetLastError());
        }

        if (pVAE && InstallHook(&g_hookVAE, pVAE, (void*)Hooked_VirtualAllocEx)) {
            printf("  [ + ] Hooked VirtualAllocEx at " FMT_PTR "\n", CAST_PTR(pVAE));
            Log("[ + ] Hooked VirtualAllocEx at " FMT_PTR "\n", CAST_PTR(pVAE));
        } else {
            printf("  [ - ] FAILED to hook VirtualAllocEx (err=%lu)\n", GetLastError());
        }

        printf("\n  [ I ] Intercepting API calls\n\n");
        Log("[ ? ] Interception started \n\n");
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        RemoveHook(&g_hookWPM);
        RemoveHook(&g_hookVAE);

        Log("\n[ + ] Interception ended. Total dumps: %ld \n", (long)g_dumpIndex);

        if (g_logFile) {
            fclose(g_logFile);
            g_logFile = NULL;
        }

        DeleteCriticalSection(&g_logCS);
        DeleteCriticalSection(&g_allocCS);

        FreeConsole();
    }

    return TRUE;
}
