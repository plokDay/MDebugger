#pragma once
#include "CPE.h"
#include <windows.h>
#include <vector>
using std::string;

typedef struct MMODULEINFO
{
	char    mname[226];
	BYTE*	 uStart;
	DWORD	 uSize;
}MMODULEINFO, *PMMODULEINFO;
// 用于保存所有的插件信息
typedef struct _PLGINFO
{
	HMODULE Base = 0;			// 加载基质
	char name[32] = { 0 };		// 插件的名称
} PLGINFO, *PPLGINFO;
//函数指针
using PFUNC1 = void(*)(char*);
using PFUNC2 = void(*)();

//调试器
//调试子系统的建立，处理用户接受到的调试信息
//获取用户的输入，并进行响应的反馈
class Debugger: public CPE
{
private:
	DEBUG_EVENT debug_event = { 0 };//保存调试事件的结构体
	DWORD CountinueStatus = DBG_CONTINUE;//保存处理的结果
	HANDLE hdThread;//异常产生时对应的线程句柄
	HANDLE hdProcess;//异常产生时对应的进程句柄
	HANDLE hp;//符号进程句柄
	bool isMainBp = true;//是否断在模块入口点
	bool isMp = false;//是否有内存断点

public:
	static bool isTf;//是否有TF断点
	static bool isHd;//是否有硬件断点
	static bool isPer;//是否有永久断点
	static bool isHdPer;//是否硬件永久断点

	char DLLPATH[MAX_PATH];//注入的路径

	void open(LPCSTR file_path);//接收一个路径
	void open(DWORD pid);
	void run();//接收并处理调试事件
	LPVOID OEPEntry = 0;//OEP
	LPVOID BaseImage = 0;//加载基址
	std::vector<PLGINFO> plugins;
private:
	void MOpenHandle();
	void MCloseHandle();
	void OnExceptionEvent();//用于处理接收到的异常事件
	void GetCommand();//接收用户输入
	void StepBy();//单步步过
	void ShowRegisters();//查看寄存器
	void ModifyRegisters();//修改寄存器
	void ShowMem();//查看内存
	void ModifyMem();//修改内存
	void ModifyDisasm(LPVOID addr);//修改汇编指令
	void ListModule(std::vector<MMODULEINFO>& mModule);
	void ShowStack();
	int HidePEB(HANDLE hProcess, HANDLE hThread);
	string GetFunctionName( SIZE_T nAddress);
	void ShowDisasm( LPVOID pAddress, DWORD nLen);
	void inject();
	void initPlugin();
	void runPlugin();
	void mDump();
};


