#include <Windows.h>
#include <cstdio>
HANDLE GetAccessToken(DWORD pid)
{
	HANDLE hProcess = {};
	HANDLE AccessToken = {};
	DWORD LastError;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (!hProcess)
	{
		LastError = GetLastError();
		printf("[-] OpenProcess() ERROR : %d\n", LastError);
		return (HANDLE)NULL;
	}
	if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken))
	{
		LastError = GetLastError();
		printf("[-] OpenProcessToken() ERROR : %d\n", LastError);
		return (HANDLE)NULL;
	}
	return AccessToken;
}