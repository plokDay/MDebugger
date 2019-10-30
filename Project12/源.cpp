#include <iostream>
#include <windows.h>
#include"TlHelp32.h"
#include "Debugger.h"
#include "Psapi.h"
#include "CPE.h"
//遍历进程
void GetAllProcess()
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		
		PROCESSENTRY32 proc = { sizeof(PROCESSENTRY32) };
		Process32First(hSnap, &proc);

		do
		{
			if (proc.th32ProcessID!=0)
			{
				printf("%d\t\t%s\n", proc.th32ProcessID, proc.szExeFile);

			}

		} while (Process32Next(hSnap, &proc));
	}

}
//PID->Path
void PID2Path(TCHAR * path,DWORD pid)
{
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProc!=INVALID_HANDLE_VALUE)
	{
		GetModuleFileNameEx(hProc, NULL, path, MAX_PATH);

	}
}
BOOL WINAPI EnablePrivileges()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return(FALSE);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME,
		&tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
		(PTOKEN_PRIVILEGES)NULL, 0);

	if (GetLastError() != ERROR_SUCCESS)
		return FALSE;

	return TRUE;
}
int main(void)
{
	setlocale(LC_ALL, "chs");
	EnablePrivileges();
	Debugger debugger;
	while (true)
	{
		system("cls");
		printf("=====Welcome to MDebugger=====\n");
		printf("1.Open\n2.Attach\n3.exit\n");
		int mOption = 0;
		scanf_s("%d", &mOption);
		getchar();
		switch (mOption)
		{
		case 1:{
			printf("path: ");
			TCHAR mPath[MAX_PATH] = { 0 };
			scanf_s("%s", mPath,MAX_PATH);
			
			bool isPe = debugger.InitPE(mPath);
			if (!isPe)
			{
				printf("不是PE文件\n");
				exit(0);
			}
			debugger.open(mPath);
			
			debugger.run();

		}break;
		case 2:
		{
			GetAllProcess();
			DWORD pid=0;
			printf("PID: ");
			scanf_s("%d", &pid);
		
			TCHAR mPath[MAX_PATH] = { 0 };
			PID2Path(mPath, pid);
			bool isPe = debugger.InitPE(mPath);
			if (!isPe)
			{
				printf("不是PE文件\n");
				exit(0);
			}
			debugger.open(pid);
			
			debugger.run();
			
		}break;
		case 3:exit(0); break;
		default:break;
		}
	}
	return 0;
}