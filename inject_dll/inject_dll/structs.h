#pragma once
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _INITIAL_TEB {
	PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

struct NtCreateThreadExBuffer
{
	SIZE_T Size;
	SIZE_T Unknown1;
	SIZE_T Unknown2;
	PULONG Unknown3;
	SIZE_T Unknown4;
	SIZE_T Unknown5;
	SIZE_T Unknown6;
	PULONG Unknown7;
	SIZE_T Unknown8;
};


//injections//

typedef NTSTATUS(NTAPI* pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI* pLdrLoadDll)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(OUT PHANDLE hThread, IN  ACCESS_MASK DesiredAccess, IN  POBJECT_ATTRIBUTES ObjectAttributes, IN HANDLE ProcessHandle, IN  LPTHREAD_START_ROUTINE  lpStartAddress, IN  LPVOID lpParameter, IN  BOOL CreateSuspended, IN DWORD StackZeroBits, IN  DWORD SizeOfStackCommit, IN  DWORD SizeOfstackReserve, LPVOID);
typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);


class cavedata_ldr
{
public:
	UNICODE_STRING path;
	HANDLE OUT_HANDLE;
	DWORD Addr_LdrLoadDll;
};

typedef struct _THREAD_DATA
{
	pRtlInitUnicodeString fnRtlInitUnicodeString;
	pLdrLoadDll fnLdrLoadDll;
	UNICODE_STRING UnicodeString;
	WCHAR DllName[260];
	PWCHAR DllPath;
	ULONG Flags;
	HANDLE ModuleHandle;
}THREAD_DATA, * PTHREAD_DATA;