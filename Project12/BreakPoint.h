#pragma once
#include <windows.h>
#include <vector>
#include "CPE.h"
// DR7�Ĵ����ṹ��
typedef struct _DBG_REG7
{
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// ��������Ч�ռ�
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} Dr7, *PDr7;
typedef struct _BREAKPOINTINFO
{
	LPVOID addr = 0;
	BYTE old_opcode = 0;
}BREAKPOINTINFO,*PBREAKPOINTINFO;
typedef struct 
{
	LPVOID addr = 0;
	int  hType = 0;
}HDBPINFO, *PHDBPINFO;
//�ϵ��࣬һ�������࣬ʵ���˵���֧�ֵ����жϵ����
//���öϵ㣬ɾ���ϵ㣬�޸��ϵ�
class BreakPoint:public CPE
{
private:
	
public:
	static DWORD oldProtect;
	static DWORD newProtect;//�ڴ�ϵ��±�������
	//ά��һ���ϵ��������������жϵ���Ϣ
	static std::vector<BREAKPOINTINFO> vecBreakpoint;
	static std::vector<HDBPINFO> vecHdbp;

	static LPVOID m_memBP;
public:
	BreakPoint();
	~BreakPoint();
	static void SetCcBreakpoint(HANDLE hprocess, HANDLE hthread, LPVOID addr);//��������ϵ�
	static void FixCcBreakpoint(HANDLE hprocess,HANDLE hThread, LPVOID addr);//�޸�����ϵ�
	static void SetTfBreakpoint(HANDLE hThread);//���õ����ϵ�
	static void SetHdBreakpoint(HANDLE hThread, LPVOID addr,int type,int len,  bool insert=0 );//����Ӳ���ϵ�
	static void FixHdBreakpoint(HANDLE hThread, LPVOID addr);//����Ӳ���ϵ�
	static void SetMemBreakpoint(HANDLE hPeocess, LPVOID addr, DWORD protect);//�����ڴ�ϵ�
	static void SetConditionBp(HANDLE hThread, HANDLE hProcess);//���������ϵ�
	

};

