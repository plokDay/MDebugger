#include "BreakPoint.h"
#include "Debugger.h"
#include <algorithm>
std::vector<BREAKPOINTINFO> BreakPoint::vecBreakpoint;
std::vector<HDBPINFO> BreakPoint::vecHdbp;
DWORD BreakPoint::oldProtect;//�ڴ�ϵ�ɱ�������
DWORD BreakPoint::newProtect;//�ڴ�ϵ��±�������
LPVOID BreakPoint::m_memBP = 0;//�ڴ�ϵ�ĵ�ַ

BreakPoint::BreakPoint()
{
}


BreakPoint::~BreakPoint()
{
}

void BreakPoint::SetCcBreakpoint(HANDLE hprocess,HANDLE hthread, LPVOID addr)
{
	//1. ��������ϵ���Ϣ�Ľṹ��
	BREAKPOINTINFO info = { addr };
	//2. ��ȡĿ���ַԭ�е�opcode�����ڻָ�ִ��
	ReadProcessMemory(hprocess, addr, &info.old_opcode, 1, NULL);
	//3. ��Ŀ����̵ĵ�ַд��\xCC�ֽ�
	WriteProcessMemory(hprocess, addr, "\xCC", 1, NULL);
	//4. �����õĶϵ���ӵ�vector
	vecBreakpoint.push_back(info);

	
}
//ע��eip-1
void BreakPoint::FixCcBreakpoint(HANDLE hprocess, HANDLE hThread, LPVOID addr)
{
	for (int i=0;i<vecBreakpoint.size();++i)
	{
		if (vecBreakpoint[i].addr==addr)
		{
			//1. ��ȡ�Ĵ�����Ϣ����eip-1
			CONTEXT context = { CONTEXT_CONTROL };
			GetThreadContext(hThread, &context);
			context.Eip = context.Eip-1;
			SetThreadContext(hThread, &context);
			//2. ��ԭ�е�����д��ָ��λ��
			WriteProcessMemory(hprocess, addr, &vecBreakpoint[i].old_opcode, 1, NULL);

			//����TF�ϵ�
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
	//1.��ȡ�Ĵ�����Ϣ
	CONTEXT ct = { CONTEXT_CONTROL };
	GetThreadContext(hThread, &ct);
	ct.EFlags |= 0x100;
	SetThreadContext(hThread, &ct);
	Debugger::isTf = true;
}

void BreakPoint::SetHdBreakpoint(HANDLE hThread, LPVOID addr, int type, int len,bool insert)
{
	
	//1.��ȡĿ���̵߳ļĴ���
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	PDr7 Dr7 = (PDr7)&ct.Dr7;
	//2. �ж���û������
	if (Dr7->L0==0)
	{
		//3. ���û�����Ϣ
		ct.Dr0 = (DWORD)addr;
		Dr7->RW0 = type;
		Dr7->LEN0 = len;
		Dr7->L0 = 1;//���öϵ�
		if (insert==0)
		{
			HDBPINFO info = { addr,type };
			vecHdbp.push_back(info);
		}
		
	}
	else if (Dr7->L1 == 0)//�ж���û������
	{
		//���û�����Ϣ
		ct.Dr1 = (DWORD)addr;
		Dr7->RW1 = type;
		Dr7->LEN1 = len;
		Dr7->L1 = 1;//���öϵ�
		if (insert == 0)
		{
			HDBPINFO info = { addr,type };
			vecHdbp.push_back(info);
		}
	}
	else if (Dr7->L2 == 0)//�ж���û������
	{
		//���û�����Ϣ
		ct.Dr2 = (DWORD)addr;
		Dr7->RW2 = type;
		Dr7->LEN2 = len;
		Dr7->L2 = 1;//���öϵ�
		if (insert == 0)
		{
			HDBPINFO info = { addr,type };
			vecHdbp.push_back(info);
		}
	}
	else if (Dr7->L3 == 0)//�ж���û������
	{
		//���û�����Ϣ
		ct.Dr3 = (DWORD)addr;
		Dr7->RW3 = type;
		Dr7->LEN3 = len;
		Dr7->L3 = 1;//���öϵ�
		if (insert == 0)
		{
			HDBPINFO info = { addr,type };
			vecHdbp.push_back(info);
		}
	}
	else
	{
		//1. ��ȡĿ���̵߳ļĴ���
		CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
		GetThreadContext(hThread, &ct);
		PDr7 Dr7 = (PDr7)&ct.Dr7;
		Dr7->L3 = 0;//������һ��
		//3. д���߳�������
		SetThreadContext(hThread, &ct);
	}
	//4. д���߳�������
	SetThreadContext(hThread, &ct);
	if (insert == 0)
	Debugger::isHd = true;

}

void BreakPoint::FixHdBreakpoint(HANDLE hThread, LPVOID addr)
{
	//1. ��ȡĿ���̵߳ļĴ���
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	PDr7 Dr7 = (PDr7)&ct.Dr7;
	//2. �ָ��������ϵ��LENλ
	switch (ct.Dr6 & 0xF)
	{
		case 1:Dr7->L0=0;break;
		case 2:Dr7->L1=0;break;
		case 4:Dr7->L2=0;break;
		case 8:Dr7->L3=0;break;
		default:break;
	}
	SetThreadContext(hThread, &ct);
	//����TF�ϵ�
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
		//��CC�ϵ�
		isCondition = true;
		SetCcBreakpoint(hProcess,hThread, addr);
	}

	
}
