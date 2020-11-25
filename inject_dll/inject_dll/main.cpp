#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#include "utils.h"
#include "Injection.h"

using namespace std;


int main()
{
	system("pause");
	printf("[+] Iniciando: \n");	

	utils::EnableDebugPrivilege(1);

	DWORD PID = utils::get_pid_process("process.exe");
	if (!PID)
	{
		printf("[-] Processo nao encontrado: \n");
		Sleep(5000);
		return 0;
	}
	
	injection::Inject_Ldr_RtlCreateUserThread(PID, "C:\\Users\\ELB\\source\\MessageBox_Dll.dll");

	getchar();
	return 1;
}