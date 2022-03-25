#include <Windows.h>
#include <TlHelp32.h>

DWORD PIDByName(const wchar_t* AProcessName)
{
    HANDLE pHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 ProcessEntry;
    DWORD pid;
    ProcessEntry.dwSize = sizeof(ProcessEntry);
    bool Loop = Process32First(pHandle, &ProcessEntry);
    while (Loop)
    {
        if (wcsstr(ProcessEntry.szExeFile, AProcessName))
        {
            pid = ProcessEntry.th32ProcessID;
            CloseHandle(pHandle);
            return pid;
        }
        Loop = Process32Next(pHandle, &ProcessEntry);
    }
    return 0;
}