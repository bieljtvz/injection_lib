#pragma once

#include "structs.h"

namespace utils
{
	void WINAPI RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);
	DWORD get_pid_process(const char* process);
	BOOL EnableDebugPrivilege(BOOL bEnable);
};

void WINAPI utils::RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
	if ((target->Buffer = (PWSTR)source))
	{
		unsigned int length = lstrlenW(source) * sizeof(WCHAR);
		if (length > 0xfffc)
			length = 0xfffc;
		target->Length = length;
		target->MaximumLength = target->Length + sizeof(WCHAR);
	}
	else target->Length = target->MaximumLength = 0;
}

DWORD utils::get_pid_process(const char *process)
{
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		DWORD Err = GetLastError();
		printf("CreateToolhelp32Snapshot failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet)
	{
		char saidaEXEFILE[256];
		sprintf_s(saidaEXEFILE, "%ws", PE32.szExeFile);

		if (!strcmp(saidaEXEFILE, process))
		{			
			return PE32.th32ProcessID;
			break;
		}
		bRet = Process32Next(hSnap, &PE32);
	}	
	CloseHandle(hSnap);
	return NULL;
}

BOOL utils::EnableDebugPrivilege(BOOL bEnable)
{
	HANDLE hToken = nullptr;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		printf("OpenProcessToken error: %d\n", GetLastError());
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		printf("LookupPrivilegeValue error: %d\n", GetLastError());
		return FALSE;
	}
	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		printf("AdjustTokenPrivileges error: %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] AdjustTokenPrivileges inciado: \n");
	return TRUE;
}
