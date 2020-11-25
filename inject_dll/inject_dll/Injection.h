#pragma once

#include "structs.h"

namespace injection
{
	DWORD get_thread_id(DWORD PID);
	HANDLE WINAPI thread_ldr(PTHREAD_DATA data);
	DWORD WINAPI stub_ldr();
	bool Inject_LoadLibrary_CreateRemoteThread(DWORD PID, const char* dll_path);
	bool Inject_LoadLibrary_NtCreateThreadEx(DWORD PID, const char* dll_path);
	bool Inject_LoadLibrary_RtlCreateUserThread(DWORD PID, const char* dll_path);
	bool Inject_LdrLoadDll_NtCreateThreadEx(DWORD PID, const char* dll_path);
	bool Inject_Ldr_RtlCreateUserThread(DWORD PID, const char* dll_path);
	bool Inject_LoadLibrary_ThreadHijackX86(DWORD PID, const char* dll_path);
};

DWORD injection::get_thread_id(DWORD PID)
{
	THREADENTRY32 te32;	
	te32.dwSize = sizeof(te32);
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(hSnap, &te32);
	while (Thread32Next(hSnap, &te32))
	{
		if (te32.th32OwnerProcessID == PID)
		{
			CloseHandle(hSnap);
			return te32.th32ThreadID;
			break;
		}
	}	
	CloseHandle(hSnap);
	return NULL;
}

HANDLE WINAPI injection::thread_ldr(PTHREAD_DATA data)
{
	data->fnRtlInitUnicodeString(&data->UnicodeString, data->DllName);
	data->fnLdrLoadDll(data->DllPath, data->Flags, &data->UnicodeString, &data->ModuleHandle);
	return data->ModuleHandle;
}

DWORD WINAPI injection::stub_ldr()
{
	return 0;
}

bool injection::Inject_LoadLibrary_CreateRemoteThread(DWORD PID, const char * dll_path)
{
	LPVOID LoadLibrary_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, PID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("[-] Falha ao abrir processo: %X\n", GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	LPVOID Memory = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, (LPVOID)Memory, dll_path, strlen(dll_path) + 1, NULL); 

	HANDLE RemoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibrary_Addr, (LPVOID)Memory, NULL, NULL);

	if (RemoteThread == INVALID_HANDLE_VALUE)
	{
		printf("[-] Erro ao criar thread: %X", GetLastError());
		return 0;
	}
	
	printf("[+] Dll injetada com sucesso: \n");

	CloseHandle(hProcess);
	return 1;
}

bool injection::Inject_LoadLibrary_NtCreateThreadEx(DWORD PID, const char* dll_path)
{
	
	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, PID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("[-] Falha ao abrir processo: %X\n", GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	LPVOID LoadLibrary_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	LPVOID NtCreateThread_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

	LPVOID Memory = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, (LPVOID)Memory, dll_path, strlen(dll_path) + 1, NULL);

	HANDLE Thread_Handle = INVALID_HANDLE_VALUE;

	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)NtCreateThread_Addr;

	////////////////////////
	NtCreateThreadExBuffer ntbuffer;

	memset(&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));
	ULONG temp0[2];
	ULONG temp1;

	ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntbuffer.Unknown1 = 0x10003;
	ntbuffer.Unknown2 = sizeof(temp0);
	ntbuffer.Unknown3 = temp0;
	ntbuffer.Unknown4 = NULL;
	ntbuffer.Unknown5 = 0x10004;
	ntbuffer.Unknown6 = sizeof(temp1);
	ntbuffer.Unknown7 = &temp1;
	ntbuffer.Unknown8 = NULL;
	/////////////////////////


	auto status = NtCreateThreadEx(&Thread_Handle, GENERIC_ALL, nullptr, hProcess, (LPTHREAD_START_ROUTINE)LoadLibrary_Addr, Memory, NULL, 0, 0, 0, &ntbuffer);
	if (status != 0)
	{
		printf("[-] Erro ao tentar chamar NtCreateThreadEx: %X", status);
		CloseHandle(Thread_Handle);
		CloseHandle(hProcess);
		return 0;
	}
	
	printf("[+] Dll injetada com sucesso: \n");
	CloseHandle(Thread_Handle);
	CloseHandle(hProcess);
	return status;
}

bool injection::Inject_LoadLibrary_RtlCreateUserThread(DWORD PID, const char* dll_path)
{
	
	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, PID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("[-] Falha ao abrir processo: %X\n", GetLastError());
		CloseHandle(hProcess);
		return 0;
	}


	LPVOID LoadLibrary_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	LPVOID RtlCreateUserThread_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");

	LPVOID Memory = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, (LPVOID)Memory, dll_path, strlen(dll_path) + 1, NULL);

	pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)RtlCreateUserThread_Addr;

	HANDLE out_handle = INVALID_HANDLE_VALUE;
	CLIENT_ID cid;

	auto status = RtlCreateUserThread(hProcess,nullptr,0,0,0,0, LoadLibrary_Addr,Memory, &out_handle, &cid);
	if (status != 0)
	{
		printf("[-] Erro ao tentar chamar RtlCreateUserThread: %X\n", status);
		CloseHandle(out_handle);
		CloseHandle(hProcess);
		return 0;
	}

	CloseHandle(out_handle);
	CloseHandle(hProcess);
	printf("[+] Dll injetada com sucesso: \n");
	return 1;
}

bool injection::Inject_LdrLoadDll_NtCreateThreadEx(DWORD PID, const char* dll_path)
{
	
	LPVOID NtCreateThread_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	LPVOID LdrLoadDll_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");
	LPVOID RtlInitUnicodeString_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, PID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("[-] Falha ao abrir processo: %X\n", GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	///////Init////////	

	size_t len = strlen(dll_path) + 1;
	size_t converted = 0;
	wchar_t* copy_wc_path;
	copy_wc_path = (wchar_t*)malloc(len * sizeof(wchar_t));
	mbstowcs_s(&converted, copy_wc_path, len, dll_path, _TRUNCATE);

	THREAD_DATA data;
	data.fnRtlInitUnicodeString = (pRtlInitUnicodeString)RtlInitUnicodeString_Addr;
	data.fnLdrLoadDll = (pLdrLoadDll)LdrLoadDll_Addr;
	memcpy(data.DllName, copy_wc_path, (wcslen(copy_wc_path) + 1) * sizeof(WCHAR));
	data.DllPath = NULL;
	data.Flags = 0;
	data.ModuleHandle = INVALID_HANDLE_VALUE;

	LPVOID pThreadData = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pThreadData, &data, sizeof(data), NULL);
	DWORD SizeOfCode = (DWORD)injection::stub_ldr - (DWORD)injection::thread_ldr;
	LPVOID pCode = VirtualAllocEx(hProcess, NULL, SizeOfCode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, pCode, (PVOID)injection::thread_ldr, SizeOfCode, NULL);

	////////Thread////////////
	//x64
	//
	NtCreateThreadExBuffer ntbuffer;

	memset(&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));
	ULONG temp0[2];
	ULONG temp1;

	ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntbuffer.Unknown1 = 0x10003;
	ntbuffer.Unknown2 = sizeof(temp0);
	ntbuffer.Unknown3 = temp0;
	ntbuffer.Unknown4 = NULL;
	ntbuffer.Unknown5 = 0x10004;
	ntbuffer.Unknown6 = sizeof(temp1);
	ntbuffer.Unknown7 = &temp1;
	ntbuffer.Unknown8 = NULL;	

	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)NtCreateThread_Addr;
	HANDLE out_thread = INVALID_HANDLE_VALUE;

	auto status = NtCreateThreadEx(&out_thread, GENERIC_ALL, nullptr, hProcess, (LPTHREAD_START_ROUTINE)pCode, pThreadData, NULL, 0, 0, 0, &ntbuffer);
	if (status != 0)
	{
		printf("[-] Erro ao tentar chamar NtCreateThreadEx: %X", status);
		CloseHandle(out_thread);
		CloseHandle(hProcess);
		return 0;
	}

	CloseHandle(out_thread);
	CloseHandle(hProcess);

	printf("[+] Dll injetada com sucesso: (%X)\n", status);

	return 1;
}

bool injection::Inject_Ldr_RtlCreateUserThread(DWORD PID, const char* dll_path)
{
	LPVOID RtlCreateUserThread_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
	LPVOID LdrLoadDll_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");
	LPVOID RtlInitUnicodeString_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, PID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("[-] Falha ao abrir processo: %X\n", GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	///////Init////////	

	size_t len = strlen(dll_path) + 1;
	size_t converted = 0;
	wchar_t* copy_wc_path;
	copy_wc_path = (wchar_t*)malloc(len * sizeof(wchar_t));
	mbstowcs_s(&converted, copy_wc_path, len, dll_path, _TRUNCATE);

	THREAD_DATA data;
	data.fnRtlInitUnicodeString = (pRtlInitUnicodeString)RtlInitUnicodeString_Addr;
	data.fnLdrLoadDll = (pLdrLoadDll)LdrLoadDll_Addr;
	memcpy(data.DllName, copy_wc_path, (wcslen(copy_wc_path) + 1) * sizeof(WCHAR));
	data.DllPath = NULL;
	data.Flags = 0;
	data.ModuleHandle = INVALID_HANDLE_VALUE;

	LPVOID pThreadData = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pThreadData, &data, sizeof(data), NULL);
	DWORD SizeOfCode = (DWORD)injection::stub_ldr - (DWORD)injection::thread_ldr;
	LPVOID pCode = VirtualAllocEx(hProcess, NULL, SizeOfCode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, pCode, (PVOID)injection::thread_ldr, SizeOfCode, NULL);

	////////Thread////////////
	pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)RtlCreateUserThread_Addr;
	HANDLE out_handle = INVALID_HANDLE_VALUE;
	CLIENT_ID cid;

	auto status = RtlCreateUserThread(hProcess, nullptr, 0, 0, 0, 0, pCode, pThreadData, &out_handle, &cid);
	if (status != 0)
	{
		printf("[-] Erro ao tentar chamar RtlCreateUserThread: %X\n", status);
		CloseHandle(out_handle);
		CloseHandle(hProcess);
		return 0;
	}

	CloseHandle(out_handle);
	CloseHandle(hProcess);
	printf("[+] Dll injetada com sucesso: \n");
	return 1;

}

bool injection::Inject_LoadLibrary_ThreadHijackX86(DWORD PID, const char* dll_path)
{
	char code[] =
	{
		0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB, 0x06, 0x00, 0x00,
		0x00, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8D, 0x93, 0x22, 0x00, 0x00, 0x00,
		0x52, 0xFF, 0xD0, 0x61, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3
	};

	DWORD THREAD_ID = injection::get_thread_id(PID);	

	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, PID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("[-] Falha ao abrir processo: %X\n", GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, THREAD_ID);
	if (hThread == INVALID_HANDLE_VALUE)
	{
		printf("[-] Falha ao abrir thread: %X\n", GetLastError());
		CloseHandle(hThread);
		return 0;
	}

	LPVOID mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	SuspendThread(hThread);

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);

	LPVOID buffer = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	LPBYTE ptr;
	ptr = (LPBYTE)buffer;

	memcpy(buffer, code, sizeof(code));

	
	while (1)
	{
		if (*ptr == 0xb8 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
		{
			*(PDWORD)(ptr + 1) = (DWORD)LoadLibraryA;
		}
		if (*ptr == 0x68 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
		{
			*(PDWORD)(ptr + 1) = ctx.Eip;
		}
		if (*ptr == 0xc3)
		{
			ptr++;
			break;
		}
		ptr++;
	}

	strcpy((char*)ptr, dll_path);

	WriteProcessMemory(hProcess, mem, buffer, sizeof(code) + strlen((char*)ptr), NULL);

	ctx.Eip = (DWORD)mem;

	SetThreadContext(hThread, &ctx);

	ResumeThread(hThread);

	VirtualFree(buffer, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	printf("[+] Dll injetada com sucesso: \n");

	return 1;
}