#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "Debugger.h"
#include "BreakPoint.h"
#include <Shlwapi.h>
#include <DbgHelp.h>
#pragma  comment (lib,"DbgHelp.lib")

//�������
#include "XEDParse/XEDParse.h"

#ifdef _WIN64
#pragma comment (lib,"XEDParse/x64/XEDParse_x64.lib")
#else
#pragma comment (lib,"XEDParse/x86/XEDParse_x86.lib")
#endif // _WIN64

//���������
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include "BeaEngine_4.1\\Win32\\headers\\BeaEngine.h"
#ifdef _WIN64
#pragma comment(lib,"BeaEngine_4.1\\Win64\\Win64\\Lib\\BeaEngine.lib")
#else
#pragma comment(lib,"BeaEngine_4.1\\Win32\\Win32\\Lib\\BeaEngine.lib")
#endif // _WIN32
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")
#pragma comment(lib, "legacy_stdio_definitions.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Dbghelp.lib")
bool Debugger::isTf = false;
bool Debugger::isHd = false;
bool Debugger::isPer = false;
bool Debugger::isHdPer = false;
void Debugger::open(LPCSTR file_path)
{
	//������̴����ɹ������ڽ��ս����̵߳ľ����id
	PROCESS_INFORMATION  process_info = { 0 };
	STARTUPINFOA startup_info = { sizeof(STARTUPINFO) };
	//���Է�ʽ��������
	BOOL result = CreateProcess(file_path, nullptr, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL, NULL, &startup_info, &process_info);
	if (result == TRUE)
	{

		CloseHandle(process_info.hThread);
		CloseHandle(process_info.hProcess);
	}

}
void Debugger::open(DWORD pid)
{

	//���Է�ʽ��������
	BOOL result = DebugActiveProcess(pid);

}
//���ط���
void LoadSymbol(HANDLE hProcess, CREATE_PROCESS_DEBUG_INFO* pInfo)
{
	//��ʼ�����Ŵ�����
	SymInitialize(hProcess, "../Symbol/", FALSE);

	//��������ļ�
	SymLoadModule64(hProcess, pInfo->hFile, NULL, NULL, (DWORD64)pInfo->lpBaseOfImage, 0);
}
//���ղ���������¼�
void Debugger::run()
{
	while (WaitForDebugEvent(&debug_event, INFINITE))
	{
		MOpenHandle();

		//dwDebugEventCode��ʾ��ǰ���յ����¼�����
		switch (debug_event.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
		{
			// �쳣�����¼�

			OnExceptionEvent();
		}break;
		case CREATE_THREAD_DEBUG_EVENT: // �̴߳����¼�	
		{
			printf("�̴߳����¼�\n");
		}break;
		case CREATE_PROCESS_DEBUG_EVENT:// ���̴����¼�
		{

			//1. OEP��CC�ϵ�
			OEPEntry = debug_event.u.CreateProcessInfo.lpStartAddress;
			BaseImage = debug_event.u.CreateProcessInfo.lpBaseOfImage;
			WriteProcessMemory(hdProcess, OEPEntry, "\xCC", 1, NULL);
			//��ʼ������
			hp = hdProcess;
			LoadSymbol(hp, &debug_event.u.CreateProcessInfo);

			printf("���̴����¼�\n"); break;
		}

		case EXIT_THREAD_DEBUG_EVENT:   // �˳��߳��¼�
			printf("�˳��߳��¼�\n"); break;
		case EXIT_PROCESS_DEBUG_EVENT:  // �˳������¼�
			printf("�˳������¼�\n"); break;
		case LOAD_DLL_DEBUG_EVENT:      // ӳ��DLL�¼�

			break;
		case UNLOAD_DLL_DEBUG_EVENT:    // ж��DLL�¼� 
			printf("ж��DLL�¼�\n"); break;
		case OUTPUT_DEBUG_STRING_EVENT: // ��������¼�
			printf("��������¼�\n"); break;
		case RIP_EVENT:                 // RIP�¼�(�ڲ�����)
			printf("RIP�¼�(�ڲ�����)\n"); break;
		}

		MCloseHandle();
		ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, CountinueStatus);
	}
}

void Debugger::MOpenHandle()
{
	hdThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
	hdProcess = OpenProcess(THREAD_ALL_ACCESS, FALSE, debug_event.dwProcessId);
}

void Debugger::MCloseHandle()
{
	CloseHandle(hdProcess);
	CloseHandle(hdThread);
}
string  PrintOpcode(BYTE* pOpcode, DWORD nSize)
{
	string nOpcode;

	for (DWORD i = 0; i < 20; i+=2)
	{
		if (i < nSize)
		{
			char tmp[50] = { 0 };
			sprintf_s(tmp, 50, "%02X ", pOpcode[i]);
			nOpcode += tmp;
		}
		else
		{
			nOpcode += "   ";
		}

	}
	return nOpcode;

}
string Debugger::GetFunctionName(SIZE_T nAddress)
{
	DWORD64  dwDisplacement = 0;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//���ݵ�ַ��ȡ������Ϣ
	if (!SymFromAddr(hp, nAddress, &dwDisplacement, pSymbol))
		return "null";

	return pSymbol->Name;
}
//��ʾ�����
void Debugger::ShowDisasm(LPVOID pAddress, DWORD nLen)
{
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	LPBYTE pOpCode = new BYTE[nLen * 15];
	SIZE_T nRead = 0;
	//��ȡ������
	if (!ReadProcessMemory(hdProcess, pAddress, pOpCode, nLen * 15, &nRead))
	{
		printf("��ȡ�����ڴ�ʧ��");
		exit(0);
	}
	//ʹ�÷���������ȡ�������Ӧ�Ļ��
	DISASM da = { 0 };
	da.EIP = (UINT_PTR)pOpCode;
	da.VirtualAddr = (UINT64)pAddress;
#ifdef _WIN64
	da.Archi = 64;
#else
	da.Archi = 0;
#endif // _WIN64
	while (nLen--)
	{
		int len = Disasm(&da);//ÿ��ָ��ĳ���
		if (len == -1)
		{
			break;
		}
		//���
		string opcode = PrintOpcode((BYTE*)da.EIP, len);
		printf("%I64X |%s ", da.VirtualAddr, opcode.c_str());

		string mDisAsm = da.CompleteInstr;
		int indexCall = mDisAsm.find("call");//���������call
		int indexJcc = mDisAsm.find("j");//���������j
		int indexPtr = -1;
		if (indexCall >= 0)
		{
			SetConsoleTextAttribute(handle, 0x0010 | 0x0080);//����ɫ

			printf("%s", mDisAsm.c_str());
			indexPtr = mDisAsm.find("ptr");
			if (indexPtr>=0)
			{
				string v = mDisAsm.substr(indexPtr + 5);
				v = v.substr(0, v.length() - 1);
				SIZE_T addr = 0;
				sscanf_s(v.c_str(), "%08X", &addr);
				SetConsoleTextAttribute(handle, 0x0020 | 0x0080);//����ɫ
				printf("\t\t%s\n", GetFunctionName(addr).c_str());
			}
			else
			{
				//�ָ��ַ/��������
				string v = mDisAsm.substr(indexCall + 5);
				SIZE_T addr = 0;
				sscanf_s(v.c_str(), "%08X", &addr);
				SetConsoleTextAttribute(handle, 0x0020 | 0x0080);//����ɫ
				printf("\t\t%s\n", GetFunctionName(addr).c_str());
			}
			SetConsoleTextAttribute(handle, 0x0004 | 0x0002 | 0x0001);//�ָ�

		}
		else if (indexJcc >= 0)
		{
			SetConsoleTextAttribute(handle, 0x0020 | 0x0040 | 0x0080);//����ɫ
			printf("%s", mDisAsm.c_str());
			//�ָ��ַ/��������
			string v = mDisAsm.substr(indexCall + 5);
			SIZE_T addr = 0;
			sscanf_s(v.c_str(), "%08X", &addr);
			SetConsoleTextAttribute(handle, 0x0020 | 0x0080);//����ɫ
			printf("\t\t%s\n", GetFunctionName(addr).c_str());
			SetConsoleTextAttribute(handle, 0x0004 | 0x0002 | 0x0001);//�ָ�

		}
		else printf("%s\n", mDisAsm.c_str());
		da.VirtualAddr += len;
		da.EIP += len;
	}

}

void Debugger::inject()
{
	DWORD dwSize = MAX_PATH;
	char PATH[MAX_PATH] = { 0 };
	QueryFullProcessImageName(GetCurrentProcess(), 0, PATH, &dwSize);
	string path = PATH;
	int index = path.find("Project12.exe");
	path = path.substr(0, index)+"dll2.dll";
	strcpy_s(DLLPATH, MAX_PATH,path.c_str());
	//PathRemoveFileSpec(PATH);
	// 2.��Ŀ�����������ռ�
	LPVOID lpPathAddr = VirtualAllocEx(
		hdProcess,					// Ŀ����̾��
		0,							// ָ�������ַ
		sizeof(DLLPATH),			// ����ռ��С
		MEM_RESERVE | MEM_COMMIT,	// �ڴ��״̬
		PAGE_EXECUTE_READWRITE);	// �ڴ�����


	// 3.��Ŀ�������д��Dll·��
	SIZE_T dwWriteSize = 0;

	WriteProcessMemory(
		hdProcess,					// Ŀ����̾��
		lpPathAddr,					// Ŀ����̵�ַ
		DLLPATH,					// д��Ļ�����
		sizeof(DLLPATH),			// ��������С
		&dwWriteSize);				// ʵ��д���С

	// 4.��Ŀ������д����߳�
	HANDLE hThread = CreateRemoteThread(
		hdProcess,					// Ŀ����̾��
		NULL,						// ��ȫ����
		NULL,						// ջ��С
		(PTHREAD_START_ROUTINE)LoadLibrary,	// �ص�����
		lpPathAddr,					// �ص���������
		NULL,						// ��־
		NULL						// �߳�ID
	);

	CloseHandle(hThread);
}

void Debugger::initPlugin()
{
	string PluginPath = "../mplugin/";
	WIN32_FIND_DATA fData = { 0 };
	HANDLE hFind = FindFirstFile("../mplugin/*", &fData);
	do
	{
		if (strcmp(fData.cFileName, ".") == 0 || strcmp(fData.cFileName, "..") == 0) {
			continue;
		}
		else
		{
			string extName = (string)fData.cFileName;
			int idx = extName.find(".");
			extName = extName.substr(idx + 1);
			if (extName == "dll")
			{
				string FilePath = PluginPath + fData.cFileName;
				HMODULE Handle = LoadLibraryA(FilePath.c_str());
				//printf("%s\n", fData.cFileName);
				PLGINFO info = { Handle };
				PFUNC1 func = (PFUNC1)GetProcAddress(Handle, "init");

				// ���������ȡ�ɹ�
				if (func)
				{
					func(fData.cFileName);
					plugins.push_back(info);
					//printf("��� %s �Ѿ���������\n", fData.cFileName);
				}
			}
		}
	} while (FindNextFile(hFind, &fData));
}

void Debugger::runPlugin()
{
	// ������������ö�Ӧ�ĺ���
	for (auto& plugin : plugins)
	{
		PFUNC2 func = (PFUNC2)GetProcAddress(plugin.Base, "run");
		if (func) func();
	}
}

void Debugger::mDump()
{
	//ɾ�����е����öϵ�
	for (auto&i:BreakPoint::vecBreakpoint)
	{
		BreakPoint::FixCcBreakpoint(hdProcess, hdThread, i.addr);
	}
	for (auto&i : BreakPoint::vecHdbp)
	{
		BreakPoint::FixHdBreakpoint(hdThread,i.addr);
	}
	DWORD nPeSize = 0;				//PEͷ
	DWORD nImageSize = 0;			//�ڴ��д�С
	DWORD nFileSize = 0;			//�ļ���С
	DWORD nSectionNum = 0;			//��������
	PBYTE nPeHeadData = nullptr;	//PE����
	PBYTE nImageBuf = nullptr;		//�ļ�����
	FILE *pFile = nullptr;			//�ļ�ָ��

	nPeHeadData = new BYTE[4096]{};

	//��ȡ�ļ�ͷ��Ϣ
	
	ReadProcessMemory(hdProcess, BaseImage, nPeHeadData, 4096,NULL);
	//��ȡPE��Ϣ
	PIMAGE_DOS_HEADER nDosHead = (PIMAGE_DOS_HEADER)nPeHeadData;
	PIMAGE_NT_HEADERS nNtHead = (PIMAGE_NT_HEADERS)(nPeHeadData + nDosHead->e_lfanew);
	PIMAGE_SECTION_HEADER nSecetionHead = IMAGE_FIRST_SECTION(nNtHead);

	//PEͷ��С
	nPeSize = nNtHead->OptionalHeader.SizeOfHeaders;
	//�ļ��ĳߴ�
	nImageSize = nNtHead->OptionalHeader.SizeOfImage;
	//��������	
	nSectionNum = nNtHead->FileHeader.NumberOfSections;


	//����exe����Ķѿռ�
	nImageBuf = new BYTE[nImageSize]{};

	//��ȡPE����
	ReadProcessMemory(hdProcess, BaseImage, nImageBuf, nPeSize, NULL);

	nFileSize += nPeSize;
	//��ȡÿ�����ε�����
	for (DWORD i = 0; i < nSectionNum; i++)
	{
		ReadProcessMemory(hdProcess, (LPVOID)((DWORD)BaseImage + nSecetionHead[i].VirtualAddress),
			nImageBuf + nSecetionHead[i].PointerToRawData, nSecetionHead[i].SizeOfRawData, NULL);

		nFileSize += nSecetionHead[i].SizeOfRawData;
	}

	//�޸��ļ�����
	nDosHead = (PIMAGE_DOS_HEADER)nImageBuf;
	nNtHead = (PIMAGE_NT_HEADERS)((DWORD)nImageBuf + nDosHead->e_lfanew);
	nNtHead->OptionalHeader.FileAlignment = nNtHead->OptionalHeader.SectionAlignment;
	
	fopen_s(&pFile, "C:/Users/jm/Desktop/dump.exe", "wb");
	fwrite(nImageBuf, nFileSize, 1, pFile);
	fclose(pFile);

	delete[] nPeHeadData;
	delete[] nImageBuf;

	printf("�ɹ�����ΪC:/Users/jm/Desktop/mdump.exe\n");
}

void Debugger::StepBy()
{
	//��ǰָ��ִ�е��ĵ�ַ
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hdThread, &ct))
	{
		printf("��ȡ�߳�������ʧ��");
		exit(0);
	}
	LPVOID addr = (LPVOID)ct.Eip;

	PBYTE pOpCode = new BYTE[15];
	SIZE_T nRead = 0;
	//��ȡ������
	if (!ReadProcessMemory(hdProcess, addr, pOpCode, 15, &nRead))
	{
		printf("��ȡ�����ڴ�ʧ��");
		exit(0);
	}

	//ʹ�÷���������ȡ�������Ӧ�Ļ��
	DISASM da = { 0 };
	da.EIP = (UINT_PTR)pOpCode;
	da.VirtualAddr = (UINT64)addr;
#ifdef _WIN64
	da.Archi = 64;
#else
	da.Archi = 0;
#endif // _WIN64
	int len = Disasm(&da);
	if (!strcmp(da.Instruction.Mnemonic, "call "))
	{
		da.VirtualAddr += len;
		da.EIP += len;
		//����һ��ָ��������int3�ϵ�
		BreakPoint::SetCcBreakpoint(hdProcess, hdThread, (LPVOID)da.VirtualAddr);
	}
	else
	{
		BreakPoint::SetTfBreakpoint(hdThread);
	}
}

void Debugger::OnExceptionEvent()
{
	BreakPoint::vecBreakpoint;
	DWORD code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;//�쳣����
	LPVOID addr = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;//�쳣��ַ
	//printf("Type(%08X):%p\n", code, addr);
	if (isMainBp)//ϵͳ�ϵ������
	{
		isMainBp = false;
		HidePEB(hdProcess, hdThread);
		initPlugin();
		inject();
		return;
	}
	if (addr == OEPEntry)
	{
		//1. ��ȡ�Ĵ�����Ϣ����eip-1
		CONTEXT context = { CONTEXT_CONTROL };
		GetThreadContext(hdThread, &context);
		context.Eip = context.Eip - 1;
		SetThreadContext(hdThread, &context);
		//2. ��ԭ�е�����д��ָ��λ��
		BYTE old = 0xE9;
		WriteProcessMemory(hdProcess, addr, &old, 1, NULL);
	}
	switch (code)
	{
	case EXCEPTION_ACCESS_VIOLATION://�ڴ�ϵ�
	{
		if (BreakPoint::m_memBP != 0)
		{

			LPVOID maddr = (LPVOID)debug_event.u.Exception.ExceptionRecord.ExceptionInformation[1];
			if (maddr == BreakPoint::m_memBP)//�������
			{
				DWORD old;
				VirtualProtectEx(hdProcess, BreakPoint::m_memBP, 1, BreakPoint::oldProtect, &BreakPoint::oldProtect);//��ȥ�ڴ�ϵ�
				BreakPoint::m_memBP = 0;
			}
			else
			{
				VirtualProtectEx(hdProcess, BreakPoint::m_memBP, 1, BreakPoint::oldProtect, &BreakPoint::oldProtect);//��ȥ�ڴ�ϵ�
				//��TF�ϵ�
				CONTEXT ct = { CONTEXT_CONTROL };
				GetThreadContext(hdThread, &ct);
				ct.EFlags |= 0x100;
				SetThreadContext(hdThread, &ct);

				isMp = true;
				return;
			}
		}

	}break;
	case EXCEPTION_BREAKPOINT://����ϵ�
	{


		BreakPoint::FixCcBreakpoint(hdProcess, hdThread, addr);
		if (isCondition)//�����ϵ�
		{
			CONTEXT ct = { CONTEXT_ALL };
			if (!GetThreadContext(hdThread, &ct)) {
				printf("��ȡ�߳�������ʧ��");
				exit(0);
			}
			//printf("%08X\n", ct.Eax);
			if (ct.Eax != condValue)
			{
				return;
			}
			else
			{
				isCondition = false;
				break;
			}
		}

	}break;
	case EXCEPTION_SINGLE_STEP://Ӳ���ϵ㣺TF������DrN�ϵ�
	{
		if (isTf)//��ͨTF
		{
			isTf = false;

			break;
		}
		
		
		if (isHd)
		{
			isHd = false;
			BreakPoint::FixHdBreakpoint(hdThread, addr);
			break;
		}
		if (isMp)
		{
			//���������ڴ�ϵ�

			isMp = false;
			VirtualProtectEx(hdProcess, BreakPoint::m_memBP, 1, BreakPoint::oldProtect, &BreakPoint::oldProtect);

			return;
		}
		if (isPer == true)//�������
		{
			isPer = false;
			for (int i = 0; i < BreakPoint::vecBreakpoint.size(); ++i)
			{
				//1. ��������ϵ���Ϣ�Ľṹ��
				BREAKPOINTINFO info = { BreakPoint::vecBreakpoint[i].addr,0 };
				//3. ��Ŀ����̵ĵ�ַд��\xCC�ֽ�
				WriteProcessMemory(hdProcess, info.addr, "\xCC", 1, NULL);

			}return;
		}
		if (isHdPer)//Ӳ������
		{
			isHdPer = false;
			for (int i = 0; i < BreakPoint::vecHdbp.size(); ++i)
			{
				BreakPoint::SetHdBreakpoint(hdThread, BreakPoint::vecHdbp[i].addr, BreakPoint::vecHdbp[i].hType, 0, 1); return;
			}
			return;
		}
		return;
	}break;
	default:
		break;
	}
	ShowDisasm((LPVOID)addr, 20);//Ĭ����ʾ20��

	GetCommand();

}

void Debugger::ShowRegisters()
{
	CONTEXT ct = { CONTEXT_ALL };

	//��ȡ�߳�������
	if (!GetThreadContext(hdThread, &ct)) {
		printf("��ȡ�߳�������ʧ��");
		exit(0);
	}

	//����Ĵ�����ֵ
	printf("Eax = %08X\tEbx = %08X\tEcx = %08X\n", ct.Eax, ct.Ebp, ct.Ecx);

	printf("Edx = %08X\tEdi = %08X\tEsi = %08X\n", ct.Edx, ct.Edi, ct.Esi);
	printf("Eip = %08X\tEbp = %08X\tEsp = %08X\n", ct.Eip, ct.Ebp, ct.Esp);

	printf("SegCs = %08X\t", ct.SegCs);
	printf("SegSs = %08X\t", ct.SegSs);
	printf("SegDs = %08X\n", ct.SegDs);
	printf("SegEs = %08X\t", ct.SegEs);
	printf("SegFs = %08X\t", ct.SegFs);
	printf("SegGs = %08X\n", ct.SegGs);
}

void Debugger::ModifyRegisters()
{
	char regi[0x10] = { 0 };
	DWORD value;
	scanf_s("%s", regi, 0x10);
	scanf_s("%d", &value);
	CONTEXT ct = { CONTEXT_ALL };
	//��ȡ�߳�������
	if (!GetThreadContext(hdThread, &ct)) {
		printf("��ȡ�߳�������ʧ��");
		exit(0);
	}
	if (!_stricmp(regi, "eax"))
	{
		ct.Eax = value;
	}
	else if (!_stricmp(regi, "ebx"))
	{
		ct.Ebx = value;
	}
	else if (!_stricmp(regi, "ecx"))
	{
		ct.Ecx = value;
	}
	else if (!_stricmp(regi, "edx"))
	{
		ct.Edx = value;
	}
	else if (!_stricmp(regi, "esi"))
	{
		ct.Esi = value;
	}
	else if (!_stricmp(regi, "edi"))
	{
		ct.Edi = value;
	}
	else if (!_stricmp(regi, "esp"))
	{
		ct.Esp = value;
	}
	else if (!_stricmp(regi, "eip"))
	{
		ct.Eip = value;
	}
	else if (!_stricmp(regi, "ebp"))
	{
		ct.Ebp = value;
	}

	if (!SetThreadContext(hdThread, &ct))
	{
		printf("�����߳�������ʧ��");
		exit(0);
	}

}
// ��ӡ�ڴ�
void printop(SIZE_T addr, LPBYTE pOpcode, int nSize)
{
	unsigned char ch = 10;
	DWORD tmp = 0;
	for (int l = 0; l < 10; ++l)//Ĭ����ʾ10��
	{
		printf("%08X |", addr);
		for (int i = 0; i < nSize; ++i)
		{
			tmp = pOpcode[i];
			printf(" %02X ", tmp);
		}
// 		printf("\t");
// 		for (int i = 0; i < nSize; ++i)
// 		{
// 			if (tmp > 33 || tmp < 126)
// 			{
// 				printf_s("%c", tmp);
// 			}
// 		}
		printf("\n");
		pOpcode += nSize;
		addr += nSize;
	}

}
void Debugger::ShowMem()
{
	LPVOID addr = 0;

	scanf_s("%x", &addr);
	LPBYTE pByte = new BYTE[16];
	SIZE_T read = 0;
	//��ȡ������
	if (!ReadProcessMemory(hdProcess, addr, pByte, 16, &read))
	{
		printf("��ȡ�ڴ�ʧ��");
		exit(0);
	}
	printop((SIZE_T)addr, pByte, 16);
}

void Debugger::ModifyMem()
{
	int addr = 0;
	scanf_s("%x", &addr);
	int value = 0;
	scanf_s("%x", &value);
	SIZE_T write = 0;
	if (!WriteProcessMemory(hdProcess, &addr, &value, 1, &write))
	{
		printf("д������ڴ�ʧ��");
		exit(0);
	}
}

void Debugger::ModifyDisasm(LPVOID addr)
{
	XEDPARSE xed = { 0 };
	xed.cip = (ULONGLONG)addr;

	// ����ָ��
	printf("ָ�");
	getchar();
	gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);

	// xed.cip, ��������תƫ�Ƶ�ָ��ʱ,��Ҫ��������ֶ�
	if (XEDPARSE_OK != XEDParseAssemble(&xed))
	{
		printf("ָ�����%s\n", xed.error);
		return;
	}

	//ʹ�÷���������ȡ�������Ӧ�Ļ��
	int nLen = 10;
	int nCount = 0;
	LPBYTE pOpCode = new BYTE[64];
	SIZE_T read = 0;
	//��ȡ������
	if (!ReadProcessMemory(hdProcess, addr, pOpCode, 64, &read))
	{
		printf("��ȡ�����ڴ�ʧ��");
		exit(0);
	}

	DISASM da = { 0 };
	da.EIP = (UINT_PTR)pOpCode;
	da.VirtualAddr = (UINT64)addr;
#ifdef _WIN64
	da.Archi = 64;
#else
	da.Archi = 0;
#endif // _WIN64
	while (nLen--)
	{
		//��ȡ��Ҫ��NOP�����ֽ���
		int len = Disasm(&da);
		if (nCount >= xed.dest_size)
		{
			break;
		}
		da.VirtualAddr += len;
		da.EIP += len;
		nCount += len;
	}

	SIZE_T write = 0;
	//��NOP�����뱻���Գ���
	if (!WriteProcessMemory(hdProcess, addr, "\90", nCount, &write))
	{
		printf("д������ڴ�ʧ��");
		exit(0);
	}

	//��OPCODEд���ڴ�
	SIZE_T write1 = 0;
	if (!WriteProcessMemory(hdProcess, addr, xed.dest, xed.dest_size, &write1))
	{
		printf("д������ڴ�ʧ��");
		exit(0);
	}
}
void Debugger::ListModule(std::vector<MMODULEINFO>& mModule)
{
	//1.����ģ�����
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, debug_event.dwProcessId);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return;
	}

	//2.��һ�α���ģ��
	MODULEENTRY32 stcMd = { sizeof(stcMd) };

	printf("start\t\tsize\tname\n");
	if (Module32First(hSnap, &stcMd))
	{
		//3.ѭ������ģ��Next
		do
		{
			//mModule.push_back(tmp);
			printf("%08X\t%d\t%s\n", stcMd.modBaseAddr, stcMd.modBaseSize, stcMd.szModule);
		} while (Module32Next(hSnap, &stcMd));
	}
	CloseHandle(hSnap);

}
//�鿴ջ
void Debugger::ShowStack()
{
	CONTEXT ct = { CONTEXT_ALL };
	//��ȡ�߳�������
	if (!GetThreadContext(hdThread, &ct)) {
		printf("��ȡ�߳�������ʧ��");
		exit(0);
	}

	LPBYTE pByte = new BYTE[100];
	SIZE_T read = 0;
	//��ȡ������
	if (!ReadProcessMemory(hdProcess, (LPCVOID)ct.Esp, pByte, 100, &read))
	{
		printf("��ȡ�ڴ�ʧ��");
		exit(0);
	}
	int j = 0;
	for (int i = 0; i < 40; ++i)
	{

		if (i % 4 == 0)
		{
			printf("%08X |", ct.Esp + 4 * j);
			j++;
		}
		DWORD tmp = pByte[i];
		printf("%02X ", tmp);
		if ((i + 1) % 4 == 0)
		{
			printf("\n");
		}
	}
}

int Debugger::HidePEB(HANDLE hProcess, HANDLE hThread)
{

	// �����ѯ���Ļ�����Ϣ
	struct PROCESS_BASIC_INFORMATION {
		ULONG ExitStatus;		// ���̷�����
		DWORD  PebBaseAddress;  // PEB��ַ
		ULONG AffinityMask;		// CPU�׺�������
		LONG  BasePriority;		// �������ȼ�
		ULONG UniqueProcessId;  // ������PID
		ULONG InheritedFromUniqueProcessId; // ������PID
	}stcProcInfo;
	// Ŀ����̵ľ��
	// ����ͨ��������ȡ��Ŀ����̵� PEB
	NtQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&stcProcInfo,
		sizeof(stcProcInfo),
		NULL);

	WriteProcessMemory(hProcess, (LPVOID)(stcProcInfo.PebBaseAddress + 0x02), "", 1, NULL);

	// �޸�Ŀ�� PEB.NtGlobalFlag ��ֵΪ 0
	WriteProcessMemory(hProcess,
		(LPVOID)(stcProcInfo.PebBaseAddress + 0x68),
		"", 1, NULL);
	//3 PEB.ProcessHeap �ֶ�ָ��� _HEAP �ṹ�е�
	// Flags 0x40�� ForceFlags 0x44����ȷ���Ƿ񱻵��ԣ����û
	// �б����ԣ����б����ֵ�ֱ��� 2 �� 0
	LPVOID addr = 0;
	ReadProcessMemory(hProcess, (LPVOID)(stcProcInfo.PebBaseAddress + 0x18), addr, 4, NULL);
	WriteProcessMemory(hProcess, (LPVOID)((DWORD)addr + 0x40), (LPCVOID)2, 1, NULL);
	WriteProcessMemory(hProcess, (LPVOID)((DWORD)addr + 0x44), "", 1, NULL);
	return 0;

}

void Debugger::GetCommand()
{
	char input[0x100] = { 0 };
	while (true)
	{
		//��ȡ����
		printf(">> ");
		scanf_s("%s", input, 0x100);
		if (!strcmp(input, "g"))
		{
			break;
		}
		else if (!strcmp(input, "gc"))//�����ϵ�
		{
			BreakPoint::SetConditionBp(hdThread, hdProcess);
			break;
		}
		else if (!strcmp(input, "r"))
		{
			//�鿴�Ĵ���
			ShowRegisters();
		}
		else if (!strcmp(input, "rw"))
		{
			//�޸ļĴ���
			ModifyRegisters();
		}
		else if (!strcmp(input, "d"))
		{
			//�鿴�ڴ�

			ShowMem();
		}
		else if (!strcmp(input, "dw"))
		{
			//�޸��ڴ�
			ModifyMem();
		}

		else if (!strcmp(input, "u"))
		{
			//�鿴ָ��λ�õ�ָ���л��ָ��
			int addr = 0, lines = 0;
			scanf_s("%x %d", &addr, &lines);
			ShowDisasm((LPVOID)addr, lines);

		}
		else if (!strcmp(input, "uw"))
		{
			//�޸�ָ��λ�õ�ָ���л��ָ��
			int addr = 0;
			scanf_s("%x", &addr);

			ModifyDisasm((LPVOID)addr);

		}
		else if (!strcmp(input, "bp"))//����ϵ�
		{
			LPVOID addr = 0;
			scanf_s("%x", &addr);

			//scanf_s("%d", &isPermanent);
			BreakPoint::SetCcBreakpoint(hdProcess, hdThread, addr);

		}
		else if (!strcmp(input, "t"))
		{
			// ���õ����ϵ�/��������
			BreakPoint::SetTfBreakpoint(hdThread);
			break;
		}
		else if (!strcmp(input, "p"))
		{
			// ���õ�������
			StepBy();
			break;
		}
		else if (!strcmp(input, "lm"))
		{
			std::vector<MMODULEINFO>mModule;
			ListModule(mModule);
			//break;
		}
		else if (!strcmp(input, "k"))//�鿴ջ
		{
			ShowStack();
		}
		else if (!strcmp(input, "hdp"))
		{
			char htype[0x10] = { 0 };
			scanf_s("%s", htype, 0x10);

			if (!strcmp(htype, "exe"))// ����Ӳ��ִ�жϵ�
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetHdBreakpoint(hdThread, addr, 0, 0);
			}
			else if (!strcmp(htype, "w"))// ����Ӳ��д�ϵ�
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetHdBreakpoint(hdThread, addr, 1, 0);
			}
			else if (!strcmp(htype, "rw"))// ����Ӳ����д�ϵ�
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetHdBreakpoint(hdThread, addr, 3, 0);

			}
			else
			{
				printf("����ָ�����\n");
			}
		}

		else if (!strcmp(input, "mp"))
		{
			char htype[0x10] = { 0 };
			scanf_s("%s", htype, 0x10);
			if (!strcmp(htype, "w"))// �����ڴ�д�ϵ�
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetMemBreakpoint(hdProcess, addr, PAGE_READONLY);
			}
			else if (!strcmp(htype, "r"))// �����ڴ���ϵ�
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetMemBreakpoint(hdProcess, addr, PAGE_NOACCESS);
			}
			else if (!strcmp(htype, "exe"))// �����ڴ�ִ�жϵ�
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetMemBreakpoint(hdProcess, addr, PAGE_READWRITE);
			}
			else
			{
				printf("����ָ�����\n");
			}
		}

		else if (!strcmp(input, "limp"))//���������
		{
			ShowImportInfo();
		}
		else if (!strcmp(input, "lexp"))//���������
		{
			ShowExportInfo();
		}
		else if (!strcmp(input, "lplugin"))
		{
			for (auto&i: plugins)
			{
				printf("%s\n", i.name);
			}
			
		}
		else if (!strcmp(input, "rplugin"))
		{
		runPlugin();
		}
		else if (!strcmp(input, "dplugin"))
		{
		// �������д������
		for (auto& plugin : plugins)
		{
			FreeLibrary(plugin.Base);
			printf("%s���ж��\n", plugin.name);
		}

		}
		else if (!strcmp(input, "dump"))
		{
		mDump();
		}
		else if (!strcmp(input, "addr2name"))
		{
		SIZE_T addr;
		scanf_s("%08X", &addr);
		printf("%s\n", GetFunctionName(addr).c_str());

		}
		else if (!strcmp(input, "h"))
		{
		printf("addr2name\t��ַ������\nbp\t����ϵ�\nd\t�鿴�ڴ�\ndplugin\tж�ز��\ndw\t�޸�\
		�ڴ�\ndump\tDUMP\ng\tִ��\ngc [address] [condition]\t�����ϵ�\nh\t����\nhdp exe\tӲ��ִ��\
		�ϵ�\nhdp rw\tӲ����д�ϵ�\nhdp w\tӲ��д�ϵ�\nk\t�鿴ջ\nlexp\t�г�������\nlimp\t�г������\nlm\t�г�\
		ģ��\n\plugin\t�г����\nmp exe\t�ڴ�ִ�жϵ�\nmp r\t�ڴ���ʶϵ�\nmp w\t�ڴ�д�ϵ�\np\t��������\nr\t�鿴\
		�Ĵ���\nrw\t�޸ļĴ���\nrplugin\t���в��\nt\t��������\nu [Address] [line]\t�鿴���\nuw\t�޸Ļ��\n");
		}
		else
		{
			printf("����ָ�����\n");
		}
	}
}
