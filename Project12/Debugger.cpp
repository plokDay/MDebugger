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

//汇编引擎
#include "XEDParse/XEDParse.h"

#ifdef _WIN64
#pragma comment (lib,"XEDParse/x64/XEDParse_x64.lib")
#else
#pragma comment (lib,"XEDParse/x86/XEDParse_x86.lib")
#endif // _WIN64

//反汇编引擎
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
	//如果进程创建成功，用于接收进程线程的句柄和id
	PROCESS_INFORMATION  process_info = { 0 };
	STARTUPINFOA startup_info = { sizeof(STARTUPINFO) };
	//调试方式创建进程
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

	//调试方式创建进程
	BOOL result = DebugActiveProcess(pid);

}
//加载符号
void LoadSymbol(HANDLE hProcess, CREATE_PROCESS_DEBUG_INFO* pInfo)
{
	//初始化符号处理器
	SymInitialize(hProcess, "../Symbol/", FALSE);

	//载入符号文件
	SymLoadModule64(hProcess, pInfo->hFile, NULL, NULL, (DWORD64)pInfo->lpBaseOfImage, 0);
}
//接收并处理调试事件
void Debugger::run()
{
	while (WaitForDebugEvent(&debug_event, INFINITE))
	{
		MOpenHandle();

		//dwDebugEventCode表示当前接收到的事件类型
		switch (debug_event.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
		{
			// 异常调试事件

			OnExceptionEvent();
		}break;
		case CREATE_THREAD_DEBUG_EVENT: // 线程创建事件	
		{
			printf("线程创建事件\n");
		}break;
		case CREATE_PROCESS_DEBUG_EVENT:// 进程创建事件
		{

			//1. OEP设CC断点
			OEPEntry = debug_event.u.CreateProcessInfo.lpStartAddress;
			BaseImage = debug_event.u.CreateProcessInfo.lpBaseOfImage;
			WriteProcessMemory(hdProcess, OEPEntry, "\xCC", 1, NULL);
			//初始化符号
			hp = hdProcess;
			LoadSymbol(hp, &debug_event.u.CreateProcessInfo);

			printf("进程创建事件\n"); break;
		}

		case EXIT_THREAD_DEBUG_EVENT:   // 退出线程事件
			printf("退出线程事件\n"); break;
		case EXIT_PROCESS_DEBUG_EVENT:  // 退出进程事件
			printf("退出进程事件\n"); break;
		case LOAD_DLL_DEBUG_EVENT:      // 映射DLL事件

			break;
		case UNLOAD_DLL_DEBUG_EVENT:    // 卸载DLL事件 
			printf("卸载DLL事件\n"); break;
		case OUTPUT_DEBUG_STRING_EVENT: // 调试输出事件
			printf("调试输出事件\n"); break;
		case RIP_EVENT:                 // RIP事件(内部错误)
			printf("RIP事件(内部错误)\n"); break;
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
	//根据地址获取符号信息
	if (!SymFromAddr(hp, nAddress, &dwDisplacement, pSymbol))
		return "null";

	return pSymbol->Name;
}
//显示反汇编
void Debugger::ShowDisasm(LPVOID pAddress, DWORD nLen)
{
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	LPBYTE pOpCode = new BYTE[nLen * 15];
	SIZE_T nRead = 0;
	//获取机器码
	if (!ReadProcessMemory(hdProcess, pAddress, pOpCode, nLen * 15, &nRead))
	{
		printf("读取进程内存失败");
		exit(0);
	}
	//使用反汇编引擎获取机器码对应的汇编
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
		int len = Disasm(&da);//每条指令的长度
		if (len == -1)
		{
			break;
		}
		//输出
		string opcode = PrintOpcode((BYTE*)da.EIP, len);
		printf("%I64X |%s ", da.VirtualAddr, opcode.c_str());

		string mDisAsm = da.CompleteInstr;
		int indexCall = mDisAsm.find("call");//命令里包含call
		int indexJcc = mDisAsm.find("j");//命令里包含j
		int indexPtr = -1;
		if (indexCall >= 0)
		{
			SetConsoleTextAttribute(handle, 0x0010 | 0x0080);//亮蓝色

			printf("%s", mDisAsm.c_str());
			indexPtr = mDisAsm.find("ptr");
			if (indexPtr>=0)
			{
				string v = mDisAsm.substr(indexPtr + 5);
				v = v.substr(0, v.length() - 1);
				SIZE_T addr = 0;
				sscanf_s(v.c_str(), "%08X", &addr);
				SetConsoleTextAttribute(handle, 0x0020 | 0x0080);//亮绿色
				printf("\t\t%s\n", GetFunctionName(addr).c_str());
			}
			else
			{
				//分割地址/解析符号
				string v = mDisAsm.substr(indexCall + 5);
				SIZE_T addr = 0;
				sscanf_s(v.c_str(), "%08X", &addr);
				SetConsoleTextAttribute(handle, 0x0020 | 0x0080);//亮绿色
				printf("\t\t%s\n", GetFunctionName(addr).c_str());
			}
			SetConsoleTextAttribute(handle, 0x0004 | 0x0002 | 0x0001);//恢复

		}
		else if (indexJcc >= 0)
		{
			SetConsoleTextAttribute(handle, 0x0020 | 0x0040 | 0x0080);//亮黄色
			printf("%s", mDisAsm.c_str());
			//分割地址/解析符号
			string v = mDisAsm.substr(indexCall + 5);
			SIZE_T addr = 0;
			sscanf_s(v.c_str(), "%08X", &addr);
			SetConsoleTextAttribute(handle, 0x0020 | 0x0080);//亮绿色
			printf("\t\t%s\n", GetFunctionName(addr).c_str());
			SetConsoleTextAttribute(handle, 0x0004 | 0x0002 | 0x0001);//恢复

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
	// 2.在目标进程中申请空间
	LPVOID lpPathAddr = VirtualAllocEx(
		hdProcess,					// 目标进程句柄
		0,							// 指定申请地址
		sizeof(DLLPATH),			// 申请空间大小
		MEM_RESERVE | MEM_COMMIT,	// 内存的状态
		PAGE_EXECUTE_READWRITE);	// 内存属性


	// 3.在目标进程中写入Dll路径
	SIZE_T dwWriteSize = 0;

	WriteProcessMemory(
		hdProcess,					// 目标进程句柄
		lpPathAddr,					// 目标进程地址
		DLLPATH,					// 写入的缓冲区
		sizeof(DLLPATH),			// 缓冲区大小
		&dwWriteSize);				// 实际写入大小

	// 4.在目标进程中创建线程
	HANDLE hThread = CreateRemoteThread(
		hdProcess,					// 目标进程句柄
		NULL,						// 安全属性
		NULL,						// 栈大小
		(PTHREAD_START_ROUTINE)LoadLibrary,	// 回调函数
		lpPathAddr,					// 回调函数参数
		NULL,						// 标志
		NULL						// 线程ID
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

				// 如果函数获取成功
				if (func)
				{
					func(fData.cFileName);
					plugins.push_back(info);
					//printf("插件 %s 已经被加载了\n", fData.cFileName);
				}
			}
		}
	} while (FindNextFile(hFind, &fData));
}

void Debugger::runPlugin()
{
	// 遍历插件，调用对应的函数
	for (auto& plugin : plugins)
	{
		PFUNC2 func = (PFUNC2)GetProcAddress(plugin.Base, "run");
		if (func) func();
	}
}

void Debugger::mDump()
{
	//删除所有的永久断点
	for (auto&i:BreakPoint::vecBreakpoint)
	{
		BreakPoint::FixCcBreakpoint(hdProcess, hdThread, i.addr);
	}
	for (auto&i : BreakPoint::vecHdbp)
	{
		BreakPoint::FixHdBreakpoint(hdThread,i.addr);
	}
	DWORD nPeSize = 0;				//PE头
	DWORD nImageSize = 0;			//内存中大小
	DWORD nFileSize = 0;			//文件大小
	DWORD nSectionNum = 0;			//区段数量
	PBYTE nPeHeadData = nullptr;	//PE缓存
	PBYTE nImageBuf = nullptr;		//文件缓存
	FILE *pFile = nullptr;			//文件指针

	nPeHeadData = new BYTE[4096]{};

	//读取文件头信息
	
	ReadProcessMemory(hdProcess, BaseImage, nPeHeadData, 4096,NULL);
	//获取PE信息
	PIMAGE_DOS_HEADER nDosHead = (PIMAGE_DOS_HEADER)nPeHeadData;
	PIMAGE_NT_HEADERS nNtHead = (PIMAGE_NT_HEADERS)(nPeHeadData + nDosHead->e_lfanew);
	PIMAGE_SECTION_HEADER nSecetionHead = IMAGE_FIRST_SECTION(nNtHead);

	//PE头大小
	nPeSize = nNtHead->OptionalHeader.SizeOfHeaders;
	//文件的尺寸
	nImageSize = nNtHead->OptionalHeader.SizeOfImage;
	//区段数量	
	nSectionNum = nNtHead->FileHeader.NumberOfSections;


	//申请exe所需的堆空间
	nImageBuf = new BYTE[nImageSize]{};

	//读取PE数据
	ReadProcessMemory(hdProcess, BaseImage, nImageBuf, nPeSize, NULL);

	nFileSize += nPeSize;
	//读取每个区段的数据
	for (DWORD i = 0; i < nSectionNum; i++)
	{
		ReadProcessMemory(hdProcess, (LPVOID)((DWORD)BaseImage + nSecetionHead[i].VirtualAddress),
			nImageBuf + nSecetionHead[i].PointerToRawData, nSecetionHead[i].SizeOfRawData, NULL);

		nFileSize += nSecetionHead[i].SizeOfRawData;
	}

	//修改文件对齐
	nDosHead = (PIMAGE_DOS_HEADER)nImageBuf;
	nNtHead = (PIMAGE_NT_HEADERS)((DWORD)nImageBuf + nDosHead->e_lfanew);
	nNtHead->OptionalHeader.FileAlignment = nNtHead->OptionalHeader.SectionAlignment;
	
	fopen_s(&pFile, "C:/Users/jm/Desktop/dump.exe", "wb");
	fwrite(nImageBuf, nFileSize, 1, pFile);
	fclose(pFile);

	delete[] nPeHeadData;
	delete[] nImageBuf;

	printf("成功保存为C:/Users/jm/Desktop/mdump.exe\n");
}

void Debugger::StepBy()
{
	//当前指令执行到的地址
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hdThread, &ct))
	{
		printf("获取线程上下文失败");
		exit(0);
	}
	LPVOID addr = (LPVOID)ct.Eip;

	PBYTE pOpCode = new BYTE[15];
	SIZE_T nRead = 0;
	//获取机器码
	if (!ReadProcessMemory(hdProcess, addr, pOpCode, 15, &nRead))
	{
		printf("读取进程内存失败");
		exit(0);
	}

	//使用反汇编引擎获取机器码对应的汇编
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
		//在下一条指令设置上int3断点
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
	DWORD code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;//异常类型
	LPVOID addr = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;//异常地址
	//printf("Type(%08X):%p\n", code, addr);
	if (isMainBp)//系统断点就跳过
	{
		isMainBp = false;
		HidePEB(hdProcess, hdThread);
		initPlugin();
		inject();
		return;
	}
	if (addr == OEPEntry)
	{
		//1. 获取寄存器信息，将eip-1
		CONTEXT context = { CONTEXT_CONTROL };
		GetThreadContext(hdThread, &context);
		context.Eip = context.Eip - 1;
		SetThreadContext(hdThread, &context);
		//2. 将原有的数据写回指定位置
		BYTE old = 0xE9;
		WriteProcessMemory(hdProcess, addr, &old, 1, NULL);
	}
	switch (code)
	{
	case EXCEPTION_ACCESS_VIOLATION://内存断点
	{
		if (BreakPoint::m_memBP != 0)
		{

			LPVOID maddr = (LPVOID)debug_event.u.Exception.ExceptionRecord.ExceptionInformation[1];
			if (maddr == BreakPoint::m_memBP)//如果命中
			{
				DWORD old;
				VirtualProtectEx(hdProcess, BreakPoint::m_memBP, 1, BreakPoint::oldProtect, &BreakPoint::oldProtect);//除去内存断点
				BreakPoint::m_memBP = 0;
			}
			else
			{
				VirtualProtectEx(hdProcess, BreakPoint::m_memBP, 1, BreakPoint::oldProtect, &BreakPoint::oldProtect);//除去内存断点
				//下TF断点
				CONTEXT ct = { CONTEXT_CONTROL };
				GetThreadContext(hdThread, &ct);
				ct.EFlags |= 0x100;
				SetThreadContext(hdThread, &ct);

				isMp = true;
				return;
			}
		}

	}break;
	case EXCEPTION_BREAKPOINT://软件断点
	{


		BreakPoint::FixCcBreakpoint(hdProcess, hdThread, addr);
		if (isCondition)//条件断点
		{
			CONTEXT ct = { CONTEXT_ALL };
			if (!GetThreadContext(hdThread, &ct)) {
				printf("获取线程上下文失败");
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
	case EXCEPTION_SINGLE_STEP://硬件断点：TF单步，DrN断点
	{
		if (isTf)//普通TF
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
			//重新设置内存断点

			isMp = false;
			VirtualProtectEx(hdProcess, BreakPoint::m_memBP, 1, BreakPoint::oldProtect, &BreakPoint::oldProtect);

			return;
		}
		if (isPer == true)//软件永久
		{
			isPer = false;
			for (int i = 0; i < BreakPoint::vecBreakpoint.size(); ++i)
			{
				//1. 创建保存断点信息的结构体
				BREAKPOINTINFO info = { BreakPoint::vecBreakpoint[i].addr,0 };
				//3. 向目标进程的地址写入\xCC字节
				WriteProcessMemory(hdProcess, info.addr, "\xCC", 1, NULL);

			}return;
		}
		if (isHdPer)//硬件永久
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
	ShowDisasm((LPVOID)addr, 20);//默认显示20行

	GetCommand();

}

void Debugger::ShowRegisters()
{
	CONTEXT ct = { CONTEXT_ALL };

	//获取线程上下文
	if (!GetThreadContext(hdThread, &ct)) {
		printf("获取线程上下文失败");
		exit(0);
	}

	//输出寄存器的值
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
	//获取线程上下文
	if (!GetThreadContext(hdThread, &ct)) {
		printf("获取线程上下文失败");
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
		printf("设置线程上下文失败");
		exit(0);
	}

}
// 打印内存
void printop(SIZE_T addr, LPBYTE pOpcode, int nSize)
{
	unsigned char ch = 10;
	DWORD tmp = 0;
	for (int l = 0; l < 10; ++l)//默认显示10行
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
	//获取机器码
	if (!ReadProcessMemory(hdProcess, addr, pByte, 16, &read))
	{
		printf("读取内存失败");
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
		printf("写入进程内存失败");
		exit(0);
	}
}

void Debugger::ModifyDisasm(LPVOID addr)
{
	XEDPARSE xed = { 0 };
	xed.cip = (ULONGLONG)addr;

	// 接收指令
	printf("指令：");
	getchar();
	gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);

	// xed.cip, 汇编带有跳转偏移的指令时,需要配置这个字段
	if (XEDPARSE_OK != XEDParseAssemble(&xed))
	{
		printf("指令错误：%s\n", xed.error);
		return;
	}

	//使用反汇编引擎获取机器码对应的汇编
	int nLen = 10;
	int nCount = 0;
	LPBYTE pOpCode = new BYTE[64];
	SIZE_T read = 0;
	//获取机器码
	if (!ReadProcessMemory(hdProcess, addr, pOpCode, 64, &read))
	{
		printf("读取进程内存失败");
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
		//获取需要用NOP填充的字节数
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
	//将NOP填充进入被调试程序
	if (!WriteProcessMemory(hdProcess, addr, "\90", nCount, &write))
	{
		printf("写入进程内存失败");
		exit(0);
	}

	//将OPCODE写入内存
	SIZE_T write1 = 0;
	if (!WriteProcessMemory(hdProcess, addr, xed.dest, xed.dest_size, &write1))
	{
		printf("写入进程内存失败");
		exit(0);
	}
}
void Debugger::ListModule(std::vector<MMODULEINFO>& mModule)
{
	//1.创建模块快照
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, debug_event.dwProcessId);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return;
	}

	//2.第一次遍历模块
	MODULEENTRY32 stcMd = { sizeof(stcMd) };

	printf("start\t\tsize\tname\n");
	if (Module32First(hSnap, &stcMd))
	{
		//3.循环遍历模块Next
		do
		{
			//mModule.push_back(tmp);
			printf("%08X\t%d\t%s\n", stcMd.modBaseAddr, stcMd.modBaseSize, stcMd.szModule);
		} while (Module32Next(hSnap, &stcMd));
	}
	CloseHandle(hSnap);

}
//查看栈
void Debugger::ShowStack()
{
	CONTEXT ct = { CONTEXT_ALL };
	//获取线程上下文
	if (!GetThreadContext(hdThread, &ct)) {
		printf("获取线程上下文失败");
		exit(0);
	}

	LPBYTE pByte = new BYTE[100];
	SIZE_T read = 0;
	//获取机器码
	if (!ReadProcessMemory(hdProcess, (LPCVOID)ct.Esp, pByte, 100, &read))
	{
		printf("读取内存失败");
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

	// 保存查询到的基本信息
	struct PROCESS_BASIC_INFORMATION {
		ULONG ExitStatus;		// 进程返回码
		DWORD  PebBaseAddress;  // PEB地址
		ULONG AffinityMask;		// CPU亲和性掩码
		LONG  BasePriority;		// 基本优先级
		ULONG UniqueProcessId;  // 本进程PID
		ULONG InheritedFromUniqueProcessId; // 父进程PID
	}stcProcInfo;
	// 目标进程的句柄
	// 可以通过函数获取到目标进程的 PEB
	NtQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&stcProcInfo,
		sizeof(stcProcInfo),
		NULL);

	WriteProcessMemory(hProcess, (LPVOID)(stcProcInfo.PebBaseAddress + 0x02), "", 1, NULL);

	// 修改目标 PEB.NtGlobalFlag 的值为 0
	WriteProcessMemory(hProcess,
		(LPVOID)(stcProcInfo.PebBaseAddress + 0x68),
		"", 1, NULL);
	//3 PEB.ProcessHeap 字段指向的 _HEAP 结构中的
	// Flags 0x40和 ForceFlags 0x44可以确定是否被调试，如果没
	// 有被调试，其中保存的值分别是 2 和 0
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
		//获取命令
		printf(">> ");
		scanf_s("%s", input, 0x100);
		if (!strcmp(input, "g"))
		{
			break;
		}
		else if (!strcmp(input, "gc"))//条件断点
		{
			BreakPoint::SetConditionBp(hdThread, hdProcess);
			break;
		}
		else if (!strcmp(input, "r"))
		{
			//查看寄存器
			ShowRegisters();
		}
		else if (!strcmp(input, "rw"))
		{
			//修改寄存器
			ModifyRegisters();
		}
		else if (!strcmp(input, "d"))
		{
			//查看内存

			ShowMem();
		}
		else if (!strcmp(input, "dw"))
		{
			//修改内存
			ModifyMem();
		}

		else if (!strcmp(input, "u"))
		{
			//查看指定位置的指定行汇编指令
			int addr = 0, lines = 0;
			scanf_s("%x %d", &addr, &lines);
			ShowDisasm((LPVOID)addr, lines);

		}
		else if (!strcmp(input, "uw"))
		{
			//修改指定位置的指定行汇编指令
			int addr = 0;
			scanf_s("%x", &addr);

			ModifyDisasm((LPVOID)addr);

		}
		else if (!strcmp(input, "bp"))//软件断点
		{
			LPVOID addr = 0;
			scanf_s("%x", &addr);

			//scanf_s("%d", &isPermanent);
			BreakPoint::SetCcBreakpoint(hdProcess, hdThread, addr);

		}
		else if (!strcmp(input, "t"))
		{
			// 设置单步断点/单步步入
			BreakPoint::SetTfBreakpoint(hdThread);
			break;
		}
		else if (!strcmp(input, "p"))
		{
			// 设置单步步过
			StepBy();
			break;
		}
		else if (!strcmp(input, "lm"))
		{
			std::vector<MMODULEINFO>mModule;
			ListModule(mModule);
			//break;
		}
		else if (!strcmp(input, "k"))//查看栈
		{
			ShowStack();
		}
		else if (!strcmp(input, "hdp"))
		{
			char htype[0x10] = { 0 };
			scanf_s("%s", htype, 0x10);

			if (!strcmp(htype, "exe"))// 设置硬件执行断点
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetHdBreakpoint(hdThread, addr, 0, 0);
			}
			else if (!strcmp(htype, "w"))// 设置硬件写断点
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetHdBreakpoint(hdThread, addr, 1, 0);
			}
			else if (!strcmp(htype, "rw"))// 设置硬件读写断点
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetHdBreakpoint(hdThread, addr, 3, 0);

			}
			else
			{
				printf("输入指令错误\n");
			}
		}

		else if (!strcmp(input, "mp"))
		{
			char htype[0x10] = { 0 };
			scanf_s("%s", htype, 0x10);
			if (!strcmp(htype, "w"))// 设置内存写断点
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetMemBreakpoint(hdProcess, addr, PAGE_READONLY);
			}
			else if (!strcmp(htype, "r"))// 设置内存读断点
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetMemBreakpoint(hdProcess, addr, PAGE_NOACCESS);
			}
			else if (!strcmp(htype, "exe"))// 设置内存执行断点
			{
				LPVOID addr = 0;
				scanf_s("%x", &addr);
				BreakPoint::SetMemBreakpoint(hdProcess, addr, PAGE_READWRITE);
			}
			else
			{
				printf("输入指令错误\n");
			}
		}

		else if (!strcmp(input, "limp"))//解析导入表
		{
			ShowImportInfo();
		}
		else if (!strcmp(input, "lexp"))//解析导入表
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
		// 和上面的写法类似
		for (auto& plugin : plugins)
		{
			FreeLibrary(plugin.Base);
			printf("%s插件卸载\n", plugin.name);
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
		printf("addr2name\t地址求函数名\nbp\t软件断点\nd\t查看内存\ndplugin\t卸载插件\ndw\t修改\
		内存\ndump\tDUMP\ng\t执行\ngc [address] [condition]\t条件断点\nh\t帮助\nhdp exe\t硬件执行\
		断点\nhdp rw\t硬件读写断点\nhdp w\t硬件写断点\nk\t查看栈\nlexp\t列出导出表\nlimp\t列出导入表\nlm\t列出\
		模块\n\plugin\t列出插件\nmp exe\t内存执行断点\nmp r\t内存访问断点\nmp w\t内存写断点\np\t单步步过\nr\t查看\
		寄存器\nrw\t修改寄存器\nrplugin\t运行插件\nt\t单步步入\nu [Address] [line]\t查看汇编\nuw\t修改汇编\n");
		}
		else
		{
			printf("输入指令错误\n");
		}
	}
}
