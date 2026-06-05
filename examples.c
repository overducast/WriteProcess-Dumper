#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};

    si.cb = sizeof(si);

    if (!CreateProcessA(
            "C:\\Windows\\System32\\notepad.exe",
            NULL,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi))
    {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    Sleep(1000);

    const char payload[] =
        "Hello from WriteProcessMemory test";

    LPVOID remote =
        VirtualAllocEx(
            pi.hProcess,
            NULL,
            sizeof(payload),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);

    if (!remote)
    {
        printf("VirtualAllocEx failed: %lu\n", GetLastError());
        return 1;
    }

    SIZE_T written = 0;

    if (!WriteProcessMemory(
            pi.hProcess,
            remote,
            payload,
            sizeof(payload),
            &written))
    {
        printf("WriteProcessMemory failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Allocated remote memory at %p\n", remote);
    printf("Written %llu bytes\n",
           (unsigned long long)written);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}