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
// ���ڱ������еĲ����Ϣ
typedef struct _PLGINFO
{
	HMODULE Base = 0;			// ���ػ���
	char name[32] = { 0 };		// ���������
} PLGINFO, *PPLGINFO;
//����ָ��
using PFUNC1 = void(*)(char*);
using PFUNC2 = void(*)();

//������
//������ϵͳ�Ľ����������û����ܵ��ĵ�����Ϣ
//��ȡ�û������룬��������Ӧ�ķ���
class Debugger: public CPE
{
private:
	DEBUG_EVENT debug_event = { 0 };//��������¼��Ľṹ��
	DWORD CountinueStatus = DBG_CONTINUE;//���洦��Ľ��
	HANDLE hdThread;//�쳣����ʱ��Ӧ���߳̾��
	HANDLE hdProcess;//�쳣����ʱ��Ӧ�Ľ��̾��
	HANDLE hp;//���Ž��̾��
	bool isMainBp = true;//�Ƿ����ģ����ڵ�
	bool isMp = false;//�Ƿ����ڴ�ϵ�

public:
	static bool isTf;//�Ƿ���TF�ϵ�
	static bool isHd;//�Ƿ���Ӳ���ϵ�
	static bool isPer;//�Ƿ������öϵ�
	static bool isHdPer;//�Ƿ�Ӳ�����öϵ�

	char DLLPATH[MAX_PATH];//ע���·��

	void open(LPCSTR file_path);//����һ��·��
	void open(DWORD pid);
	void run();//���ղ���������¼�
	LPVOID OEPEntry = 0;//OEP
	LPVOID BaseImage = 0;//���ػ�ַ
	std::vector<PLGINFO> plugins;
private:
	void MOpenHandle();
	void MCloseHandle();
	void OnExceptionEvent();//���ڴ�����յ����쳣�¼�
	void GetCommand();//�����û�����
	void StepBy();//��������
	void ShowRegisters();//�鿴�Ĵ���
	void ModifyRegisters();//�޸ļĴ���
	void ShowMem();//�鿴�ڴ�
	void ModifyMem();//�޸��ڴ�
	void ModifyDisasm(LPVOID addr);//�޸Ļ��ָ��
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


