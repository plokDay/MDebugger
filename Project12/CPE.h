#pragma once

#include <windows.h>



class CPE
{
public:
	//1.读取文件
	//2.解析文件
	bool InitPE(TCHAR *path);
	bool IsPE(unsigned char* pbuff);

	PIMAGE_DOS_HEADER GetDosHeader();
	PIMAGE_NT_HEADERS GetNTHeaders();
	PIMAGE_EXPORT_DIRECTORY GetExportDirectory();
	PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor();

	DWORD RvaToFoa(DWORD dwRva);
	


	void ShowExportInfo();
	void ShowImportInfo();
	
	
public:
	static bool isCondition;
	static DWORD condValue;
private:
	TCHAR* m_path;
	DWORD m_size;
	unsigned char* m_buff;
};