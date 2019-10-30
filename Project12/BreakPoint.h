#pragma once
#include <windows.h>
#include <vector>
#include "CPE.h"
// DR7寄存器结构体
typedef struct _DBG_REG7
{
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// 保留的无效空间
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
//断点类，一个工具类，实现了调试支持的所有断点操作
//设置断点，删除断点，修复断点
class BreakPoint:public CPE
{
private:
	
public:
	static DWORD oldProtect;
	static DWORD newProtect;//内存断点新保护属性
	//维护一个断点容器，保存所有断点信息
	static std::vector<BREAKPOINTINFO> vecBreakpoint;
	static std::vector<HDBPINFO> vecHdbp;

	static LPVOID m_memBP;
public:
	BreakPoint();
	~BreakPoint();
	static void SetCcBreakpoint(HANDLE hprocess, HANDLE hthread, LPVOID addr);//设置软件断点
	static void FixCcBreakpoint(HANDLE hprocess,HANDLE hThread, LPVOID addr);//修复软件断点
	static void SetTfBreakpoint(HANDLE hThread);//设置单步断点
	static void SetHdBreakpoint(HANDLE hThread, LPVOID addr,int type,int len,  bool insert=0 );//设置硬件断点
	static void FixHdBreakpoint(HANDLE hThread, LPVOID addr);//设置硬件断点
	static void SetMemBreakpoint(HANDLE hPeocess, LPVOID addr, DWORD protect);//设置内存断点
	static void SetConditionBp(HANDLE hThread, HANDLE hProcess);//设置条件断点
	

};

