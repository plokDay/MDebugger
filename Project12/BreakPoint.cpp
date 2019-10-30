#include "BreakPoint.h"
#include "Debugger.h"
#include <algorithm>
std::vector<BREAKPOINTINFO> BreakPoint::vecBreakpoint;
std::vector<HDBPINFO> BreakPoint::vecHdbp;
DWORD BreakPoint::oldProtect;//内存断点旧保护属性
DWORD BreakPoint::newProtect;//内存断点新保护属性
LPVOID BreakPoint::m_memBP = 0;//内存断点的地址

BreakPoint::BreakPoint()
{
}


BreakPoint::~BreakPoint()
{
}

void BreakPoint::SetCcBreakpoint(HANDLE hprocess,HANDLE hthread, LPVOID addr)
{
	//1. 创建保存断点信息的结构体
	BREAKPOINTINFO info = { addr };
	//2. 读取目标地址原有的opcode，用于恢复执行
	ReadProcessMemory(hprocess, addr, &info.old_opcode, 1, NULL);
	//3. 向目标进程的地址写入\xCC字节
	WriteProcessMemory(hprocess, addr, "\xCC", 1, NULL);
	//4. 将设置的断点添加到vector
	vecBreakpoint.push_back(info);

	
}
//注意eip-1
void BreakPoint::FixCcBreakpoint(HANDLE hprocess, HANDLE hThread, LPVOID addr)
{
	for (int i=0;i<vecBreakpoint.size();++i)
	{
		if (vecBreakpoint[i].addr==addr)
		{
			//1. 获取寄存器信息，将eip-1
			CONTEXT context = { CONTEXT_CONTROL };
			GetThreadContext(hThread, &context);
			context.Eip = context.Eip-1;
			SetThreadContext(hThread, &context);
			//2. 将原有的数据写回指定位置
			WriteProcessMemory(hprocess, addr, &vecBreakpoint[i].old_opcode, 1, NULL);

			//设置TF断点
			CONTEXT ct = { CONTEXT_CONTROL };
			GetThreadContext(hThread, &ct);
			ct.EFlags |= 0x100;
			SetThreadContext(hThread, &ct);

			Debugger::isPer = true;
			break;
		}
	}
}

void BreakPoint::SetTfBreakpoint(HANDLE hThread)
{
	//1.获取寄存器信息
	CONTEXT ct = { CONTEXT_CONTROL };
	GetThreadContext(hThread, &ct);
	ct.EFlags |= 0x100;
	SetThreadContext(hThread, &ct);
	Debugger::isTf = true;
}

void BreakPoint::SetHdBreakpoint(HANDLE hThread, LPVOID addr, int type, int len,bool insert)
{
	
	//1.获取目标线程的寄存器
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	PDr7 Dr7 = (PDr7)&ct.Dr7;
	//2. 判断有没有启用
	if (Dr7->L0==0)
	{
		//3. 设置基本信息
		ct.Dr0 = (DWORD)addr;
		Dr7->RW0 = type;
		Dr7->LEN0 = len;
		Dr7->L0 = 1;//启用断点
		if (insert==0)
		{
			HDBPINFO info = { addr,type };
			vecHdbp.push_back(info);
		}
		
	}
	else if (Dr7->L1 == 0)//判断有没有启用
	{
		//设置基本信息
		ct.Dr1 = (DWORD)addr;
		Dr7->RW1 = type;
		Dr7->LEN1 = len;
		Dr7->L1 = 1;//启用断点
		if (insert == 0)
		{
			HDBPINFO info = { addr,type };
			vecHdbp.push_back(info);
		}
	}
	else if (Dr7->L2 == 0)//判断有没有启用
	{
		//设置基本信息
		ct.Dr2 = (DWORD)addr;
		Dr7->RW2 = type;
		Dr7->LEN2 = len;
		Dr7->L2 = 1;//启用断点
		if (insert == 0)
		{
			HDBPINFO info = { addr,type };
			vecHdbp.push_back(info);
		}
	}
	else if (Dr7->L3 == 0)//判断有没有启用
	{
		//设置基本信息
		ct.Dr3 = (DWORD)addr;
		Dr7->RW3 = type;
		Dr7->LEN3 = len;
		Dr7->L3 = 1;//启用断点
		if (insert == 0)
		{
			HDBPINFO info = { addr,type };
			vecHdbp.push_back(info);
		}
	}
	else
	{
		//1. 获取目标线程的寄存器
		CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
		GetThreadContext(hThread, &ct);
		PDr7 Dr7 = (PDr7)&ct.Dr7;
		Dr7->L3 = 0;//清空最后一个
		//3. 写入线程上下文
		SetThreadContext(hThread, &ct);
	}
	//4. 写入线程上下文
	SetThreadContext(hThread, &ct);
	if (insert == 0)
	Debugger::isHd = true;

}

void BreakPoint::FixHdBreakpoint(HANDLE hThread, LPVOID addr)
{
	//1. 获取目标线程的寄存器
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	PDr7 Dr7 = (PDr7)&ct.Dr7;
	//2. 恢复被触发断点的LEN位
	switch (ct.Dr6 & 0xF)
	{
		case 1:Dr7->L0=0;break;
		case 2:Dr7->L1=0;break;
		case 4:Dr7->L2=0;break;
		case 8:Dr7->L3=0;break;
		default:break;
	}
	SetThreadContext(hThread, &ct);
	//设置TF断点
	ct = { CONTEXT_CONTROL };
	GetThreadContext(hThread, &ct);
	ct.EFlags |= 0x100;
	SetThreadContext(hThread, &ct);
	

	Debugger::isHdPer = true;
}

void BreakPoint::SetMemBreakpoint(HANDLE hPeocess, LPVOID addr, DWORD protect)
{
	newProtect = protect;
 	VirtualProtectEx(hPeocess, addr, 1, protect, &oldProtect);
	m_memBP = addr;
}

void BreakPoint::SetConditionBp(HANDLE hThread,HANDLE hProcess)
{
	LPVOID addr = 0;
	scanf_s("%08X", &addr);
	string condition;
	condition.resize(30);
	scanf_s("%s", &condition[0], 30);
	int idx = condition.find("==");
	string regi;

	if (idx >= 0)
	{
		string v = condition.substr(idx + 2);
		condValue = atoi(v.c_str());
		regi = condition.substr(0, idx);
		//下CC断点
		isCondition = true;
		SetCcBreakpoint(hProcess,hThread, addr);
	}

	
}
