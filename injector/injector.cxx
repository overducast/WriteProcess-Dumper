#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "kernel32.lib")

static void TrimNewline(char* s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' '))
        s[--len] = '\0';
}

static void StripQuotes(char* s)
{
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

static WORD GetPEMachine(const char* path)
{
    FILE* f = NULL;
    fopen_s(&f, path, "rb");
    if (!f) return 0;

    IMAGE_DOS_HEADER dos;
    if (fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fclose(f);
        return 0;
    }

    if (fseek(f, dos.e_lfanew, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    DWORD peSig = 0;
    if (fread(&peSig, sizeof(peSig), 1, f) != 1 || peSig != IMAGE_NT_SIGNATURE) {
        fclose(f);
        return 0;
    }

    WORD machine = 0;
    fread(&machine, sizeof(machine), 1, f);
    fclose(f);
    return machine;
}

int main()
{
    char exePath[MAX_PATH] = {};
    char dllPath[MAX_PATH] = {};

    printf("  [ ? ] Path to target .exe : ");
    fgets(exePath, MAX_PATH, stdin);
    TrimNewline(exePath);
    StripQuotes(exePath);

    printf("  [ ? ] Path to dumper .dll : ");
    fgets(dllPath, MAX_PATH, stdin);
    TrimNewline(dllPath);
    StripQuotes(dllPath);

    char fullExePath[MAX_PATH] = {};
    char fullDllPath[MAX_PATH] = {};
    GetFullPathNameA(exePath, MAX_PATH, fullExePath, NULL);
    GetFullPathNameA(dllPath, MAX_PATH, fullDllPath, NULL);

    if (GetFileAttributesA(fullExePath) == INVALID_FILE_ATTRIBUTES) {
        printf("  [ - ] ERROR: Target EXE not found: %s\n", fullExePath);
        return 1;
    }
    if (GetFileAttributesA(fullDllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("  [ - ] ERROR: Dumper DLL not found: %s\n", fullDllPath);
        return 1;
    }

    WORD exeMachine = GetPEMachine(fullExePath);
    WORD dllMachine = GetPEMachine(fullDllPath);

    if (exeMachine == 0) {
        printf("  [ - ] ERROR: Could not read PE header from target EXE: %s\n", fullExePath);
        return 1;
    }

    const char* archStr = "unknown";
    if (exeMachine == IMAGE_FILE_MACHINE_I386)  archStr = "x86 (32-bit)";
    if (exeMachine == IMAGE_FILE_MACHINE_AMD64) archStr = "x64 (64-bit)";

    printf("\n");
    printf("  [ * ] Target EXE  : %s\n", fullExePath);
    printf("  [ * ] Target arch : %s\n", archStr);
    printf("  [ * ] Dumper DLL  : %s\n", fullDllPath);

#ifdef _WIN64
    if (exeMachine == IMAGE_FILE_MACHINE_I386) {
        printf("\n  [ ! ] WARNING: Target is 32-bit but this injector is 64-bit!\n");
        printf("  [ ! ] Use the x86 build of the injector instead.\n");
        return 1;
    }
#else
    if (exeMachine == IMAGE_FILE_MACHINE_AMD64) {
        printf("\n  [ ! ] WARNING: Target is 64-bit but this injector is 32-bit!\n");
        printf("  [ ! ] Use the x64 build of the injector instead.\n");
        return 1;
    }
#endif

    if (dllMachine != 0 && dllMachine != exeMachine) {
        printf("\n  [ ! ] WARNING: DLL architecture does not match the target EXE!\n");
        printf("  [ ! ]  Both must be the same (x86 or x64).\n");
        return 1;
    }

    printf("\n  [ * ] Press ENTER to launch and inject...");
    getchar();
    printf("\n");

/* create suspend process */
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    char exeDir[MAX_PATH] = {};
    strcpy_s(exeDir, fullExePath);
    char* lastSlash = strrchr(exeDir, '\\');
    if (lastSlash) *lastSlash = '\0';

    if (!CreateProcessA(fullExePath, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, exeDir, &si, &pi))
    {
        printf("  [-] ERROR: CreateProcess failed (err=%lu)\n", GetLastError());
        return 1;
    }

    printf("  [ + ] Process created  PID: %lu  TID: %lu\n", pi.dwProcessId, pi.dwThreadId);

    SIZE_T dllPathLen = strlen(fullDllPath) + 1;

    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, dllPathLen,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
	printf("  [ - ] ERROR: VirtualAllocEx failed (err=%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, remoteMem, fullDllPath, dllPathLen, NULL)) {
        printf("  [ - ] ERROR: WriteProcessMemory failed (err=%lu)\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    HMODULE hKernel32    = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hRemote = CreateRemoteThread(pi.hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLibraryA,
                                        remoteMem, 0, NULL);
    if (!hRemote) {
        printf("  [ - ]  ERROR: CreateRemoteThread failed (err=%lu)\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    printf("  [ * ] Waiting for DLL to load...\n");

    DWORD waitResult = WaitForSingleObject(hRemote, 10000);
    if (waitResult == WAIT_TIMEOUT) {
        printf("  [ ! ] WARNING: Remote thread timed out — DLL init may be hung.\n");
    }

    DWORD      rawExitCode = 0;
    ULONG_PTR  loadResult  = 0;
    GetExitCodeThread(hRemote, &rawExitCode);
    loadResult = (ULONG_PTR)rawExitCode;

    CloseHandle(hRemote);
    VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);

    if (loadResult == 0) {
        printf("  [ - ] WARNING: LoadLibraryA returned NULL — DLL may have failed to load.\n");
        printf("  [ - ] Make sure the DLL and target have matching architectures.\n");
    } else {

#ifdef _WIN64
        printf("  [ + ]  DLL injected successfully (base=0x%llx)\n",
               (unsigned long long)loadResult);
#else
        printf("  [ + ]  DLL injected successfully (base=0x%lx)\n",
               (unsigned long)loadResult);
#endif
    }
    printf("  [ * ] Resuming main thread\n");
    ResumeThread(pi.hThread);

    printf("  [ * ] Process is running. Waiting for exit\n");
    printf("  [ * ] Dump files will appear next to the DLL\n");

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    printf("\n  [*] Process exited with code: %lu\n", exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("  [ + ]  Check dump directory for .bin files\n\n");
    return 0;
}
