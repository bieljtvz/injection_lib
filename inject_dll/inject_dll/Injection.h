#pragma once

#include "structs.h"

namespace injection
{
	void __stdcall shellcode_manual(MANUAL_MAPPING_DATA* pData);
	DWORD get_thread_id(DWORD PID);
	HANDLE WINAPI thread_ldr(PTHREAD_DATA data);
	DWORD WINAPI stub_ldr();

	//Usando LoadLibrary para carregar a dll//
	bool Inject_LoadLibrary_CreateRemoteThread(DWORD PID, const char* dll_path);	//Injetor Padrão LVL 0
	bool Inject_LoadLibrary_NtCreateThreadEx(DWORD PID, const char* dll_path);		//Injetor LVL 1
	bool Inject_LoadLibrary_RtlCreateUserThread(DWORD PID, const char* dll_path);	//Injetor LVL 1
	bool Inject_LoadLibrary_ThreadHijackX86(DWORD PID, const char* dll_path);		//Injetor LVL 2

	//Usando LdrLoadDll para carregar a dll//
	bool Inject_LdrLoadDll_NtCreateThreadEx(DWORD PID, const char* dll_path);		//Injetor LVL 2
	bool Inject_LdrLoadDll_RtlCreateUserThread(DWORD PID, const char* dll_path);	//Injetor LVL 2
	bool Inject_LdrLoadDll_CreateRemoteThread(DWORD PID, const char* dll_path);		//Injetor LVL 1

	//Escrevendo a dll na memoria do processo para usala//
	bool Inject_ManualMap_CreateRemoteThread(DWORD PID, const char* dll_path);		//Broihon original				 LVL 2
	bool Inject_ManualMap_RtlCreateUserThread(DWORD PID, const char* dll_path);		//Broihon modificado by bieljtvz LVL 3
	bool Inject_ManualMap_NtCreateThreadEx(DWORD PID, const char* dll_path);		//Broihon modificado by bieljtvz LVL 3

};


void __stdcall injection::shellcode_manual(MANUAL_MAPPING_DATA* pData)
{
	if (!pData)
		return;

	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

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
	

	LPVOID Memory = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, (LPVOID)Memory, dll_path, strlen(dll_path) + 1, NULL);

	HANDLE Thread_Handle = INVALID_HANDLE_VALUE;
	LPVOID NtCreateThread_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
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

bool injection::Inject_LoadLibrary_ThreadHijackX86(DWORD PID, const char* dll_path)
{
	char shell[] =
	{
		0x60,									//pushad
		0xE8, 0x00, 0x00, 0x00, 0x00,			//call start
		0x5B,									//pop ebx
		0x81, 0xEB, 0x06, 0x00, 0x00, 0x00,		//sub ebx,start
		0xB8, 0xCC, 0xCC, 0xCC, 0xCC,			//mov eax,0xCCCCCCCC
		0x8D, 0x93, 0x22, 0x00, 0x00, 0x00,		//lea edx,[data+ebx]
		0x52,									//push edx
		0xFF, 0xD0,								//call eax
		0x61,									//popad
		0x68, 0xCC, 0xCC, 0xCC, 0xCC,			//push 0xCCCCCCCC
		0xC3									//ret
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

	memcpy(buffer, shell, sizeof(shell));

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
		if (*ptr == 0xC3)
		{
			ptr++;
			break;
		}
		ptr++;


	}


	strcpy((char*)ptr, dll_path);

	WriteProcessMemory(hProcess, mem, buffer, sizeof(shell) + strlen((char*)ptr), NULL);

	ctx.Eip = (DWORD)mem;

	SetThreadContext(hThread, &ctx);

	ResumeThread(hThread);

	VirtualFree(buffer, 0, MEM_RELEASE);

	CloseHandle(hThread);
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

bool injection::Inject_LdrLoadDll_RtlCreateUserThread(DWORD PID, const char* dll_path)
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

bool injection::Inject_LdrLoadDll_CreateRemoteThread(DWORD PID, const char* dll_path)
{
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

	auto status = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pCode, pThreadData, 0, 0);
	if (status == INVALID_HANDLE_VALUE)
	{		
		CloseHandle(status);
		CloseHandle(hProcess);
		return 0;
	}

	CloseHandle(status);
	CloseHandle(hProcess);

	printf("[+] Dll injetada com sucesso: %X \n", status);
	return 1;
	//auto status = RtlCreateUserThread(hProcess, nullptr, 0, 0, 0, 0, pCode, pThreadData, &out_handle, &cid);
}

bool injection::Inject_ManualMap_CreateRemoteThread(DWORD PID, const char* dll_path)
{
	BYTE* pSrcData = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;

	std::ifstream File(dll_path, std::ios::binary | std::ios::ate);

	if (File.fail())
	{
		printf("[-] Erro ao abrir DLL: %X\n", (DWORD)File.rdstate());
		File.close();
		return false;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000)
	{
		printf("[-] Tamanho do arquivo invalido: \n");
		File.close();
		return false;
	}

	pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData)
	{
		printf("[-] Falha ao alocar memoria: \n");
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();	

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) //"MZ"
	{
		printf("Invalid file\n");
		delete[] pSrcData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("[-] Plataforma invalida: \n");
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("[-] Plataforma invalida: \n");
		delete[] pSrcData;
		return false;
	}
#endif

	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, PID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("[-] Falha ao abrir processo: %X\n", GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			printf("[-] Falha ao allocar memoria: 0x%X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				printf("[-] Impossivel mapear secçao: 0x%x\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSrcData, &data, sizeof(data));
	WriteProcessMemory(hProcess, pTargetBase, pSrcData, 0x1000, nullptr);

	delete[] pSrcData;

	void* pShellcode = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		printf("[-] Falha ao allocar memoria: 0x%X\n", GetLastError());
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(hProcess, pShellcode, injection::shellcode_manual, 0x1000, nullptr);

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);

	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProcess, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}

	VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);

	printf("[+] Dll injetada com sucesso: \n");
} 

bool injection::Inject_ManualMap_RtlCreateUserThread(DWORD PID, const char* dll_path)
{
	BYTE* pSrcData = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;

	std::ifstream File(dll_path, std::ios::binary | std::ios::ate);

	if (File.fail())
	{
		printf("[-] Erro ao abrir DLL: %X\n", (DWORD)File.rdstate());
		File.close();
		return false;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000)
	{
		printf("[-] Tamanho do arquivo invalido: \n");
		File.close();
		return false;
	}

	pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData)
	{
		printf("[-] Falha ao alocar memoria: \n");
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) //"MZ"
	{
		printf("Invalid file\n");
		delete[] pSrcData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("[-] Plataforma invalida: \n");
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("[-] Plataforma invalida: \n");
		delete[] pSrcData;
		return false;
	}
#endif

	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, PID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("[-] Falha ao abrir processo: %X\n", GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			printf("[-] Falha ao allocar memoria: 0x%X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				printf("[-] Impossivel mapear secçao: 0x%x\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSrcData, &data, sizeof(data));
	WriteProcessMemory(hProcess, pTargetBase, pSrcData, 0x1000, nullptr);

	delete[] pSrcData;

	void* pShellcode = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		printf("[-] Falha ao allocar memoria: 0x%X\n", GetLastError());
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(hProcess, pShellcode, injection::shellcode_manual, 0x1000, nullptr);

	//
	//Thread

	LPVOID RtlCreateUserThread_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
	pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)RtlCreateUserThread_Addr;

	HANDLE out_handle = INVALID_HANDLE_VALUE;
	CLIENT_ID cid;

	////////

	auto status = RtlCreateUserThread(hProcess, nullptr, 0, 0, 0, 0, pShellcode, pTargetBase, &out_handle, &cid);
	if (status != 0)
	{
		printf("[-] Erro ao tentar chamar RtlCreateUserThread: %X\n", status);
		CloseHandle(out_handle);
		CloseHandle(hProcess);
		return 0;
	}

	CloseHandle(out_handle);

	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProcess, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}

	VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);

	printf("[+] Dll injetada com sucesso: \n");
}

bool injection::Inject_ManualMap_NtCreateThreadEx(DWORD PID, const char* dll_path)
{
	BYTE* pSrcData = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;

	std::ifstream File(dll_path, std::ios::binary | std::ios::ate);

	if (File.fail())
	{
		printf("[-] Erro ao abrir DLL: %X\n", (DWORD)File.rdstate());
		File.close();
		return false;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000)
	{
		printf("[-] Tamanho do arquivo invalido: \n");
		File.close();
		return false;
	}

	pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData)
	{
		printf("[-] Falha ao alocar memoria: \n");
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) //"MZ"
	{
		printf("Invalid file\n");
		delete[] pSrcData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("[-] Plataforma invalida: \n");
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("[-] Plataforma invalida: \n");
		delete[] pSrcData;
		return false;
	}
#endif

	HANDLE hProcess = OpenProcess(GENERIC_ALL, NULL, PID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("[-] Falha ao abrir processo: %X\n", GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			printf("[-] Falha ao allocar memoria: 0x%X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				printf("[-] Impossivel mapear secçao: 0x%x\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSrcData, &data, sizeof(data));
	WriteProcessMemory(hProcess, pTargetBase, pSrcData, 0x1000, nullptr);

	delete[] pSrcData;

	void* pShellcode = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		printf("[-] Falha ao allocar memoria: 0x%X\n", GetLastError());
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(hProcess, pShellcode, injection::shellcode_manual, 0x1000, nullptr);



	///////////Thread////////////////////////
	LPVOID NtCreateThread_Addr = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)NtCreateThread_Addr;	

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

	HANDLE Thread_Handle = INVALID_HANDLE_VALUE;

	/////////////////////////
	auto status = NtCreateThreadEx(&Thread_Handle, GENERIC_ALL, nullptr, hProcess, (LPTHREAD_START_ROUTINE)pShellcode, pTargetBase, NULL, 0, 0, 0, &ntbuffer);
	if (status != 0)
	{
		printf("[-] Erro ao tentar chamar NtCreateThreadEx: %X", status);
		CloseHandle(Thread_Handle);
		CloseHandle(hProcess);
		return 0;
	}


	//HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);

	CloseHandle(Thread_Handle);

	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProcess, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}

	VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);

	printf("[+] Dll injetada com sucesso: \n");
}

//bool SetWindowHook(DWORD PID, const char* dll_path)
//{
//	HWND hwnd = FindWindow(NULL, L"RaidCall");
//	if (hwnd == NULL) {
//		cout << "[ FAILED ] Could not find target window." << endl;
//		system("pause");
//		return EXIT_FAILURE;
//	}
//
//	// Getting the thread of the window and the PID
//	DWORD pid = NULL;
//	DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
//	if (tid == NULL) {
//		cout << "[ FAILED ] Could not get thread ID of the target window." << endl;
//		system("pause");
//		return EXIT_FAILURE;
//	}
//
//	// Loading DLL
//	HMODULE dll = LoadLibraryEx(L"C:\\Users\\ELB\\source\\repos\\MessageBox_Dll\\Debug\\MessageBox_Dll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
//	if (dll == NULL) {
//		cout << "[ FAILED ] The DLL could not be found." << endl;
//		system("pause");
//		return EXIT_FAILURE;
//	}
//
//	// Getting exported function address
//	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "NextHook");
//	if (addr == NULL) {
//		cout << "[ FAILED ] The function was not found." << endl;
//		system("pause");
//		return EXIT_FAILURE;
//	}
//
//	// Setting the hook in the hook chain
//	HHOOK handle = SetWindowsHookEx(WH_GETMESSAGE, addr, dll, tid); // Or WH_KEYBOARD if you prefer to trigger the hook manually
//	if (handle == NULL) {
//		cout << "[ FAILED ] Couldn't set the hook with SetWindowsHookEx." << endl;
//		system("pause");
//		return EXIT_FAILURE;
//	}
//
//	// Triggering the hook
//	PostThreadMessage(tid, WM_NULL, NULL, NULL);
//
//	// Waiting for user input to remove the hook
//	cout << "[ OK ] Hook set and triggered." << endl;
//	cout << "[ >> ] Press any key to unhook (This will unload the DLL)." << endl;
//	system("pause > nul");
//
//	// Unhooking
//	BOOL unhook = UnhookWindowsHookEx(handle);
//	if (unhook == FALSE) {
//		cout << "[ FAILED ] Could not remove the hook." << endl;
//		system("pause");
//		return EXIT_FAILURE;
//	}
//
//	cout << "[ OK ] Done. Press any key to exit." << endl;
//	system("pause > nul");
//	return EXIT_SUCCESS;
//}

