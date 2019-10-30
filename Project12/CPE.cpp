#include<stdio.h>
#include "CPE.h"
bool CPE::isCondition = false;
DWORD CPE::condValue = 0;
bool CPE::InitPE(TCHAR *path)
{
	m_path = path;
	HANDLE hFile = CreateFile(
		path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	m_size = GetFileSize(hFile, 0);

	m_buff = new unsigned char[m_size];
	DWORD dwReadSize;

	ReadFile(hFile, m_buff, m_size, &dwReadSize,0);
	return IsPE(m_buff);
}

bool CPE::IsPE(unsigned char* pbuff)
{
	PIMAGE_DOS_HEADER pDos = GetDosHeader();
	if (pDos->e_magic!=IMAGE_DOS_SIGNATURE)
	{
		return false;
	}
	PIMAGE_NT_HEADERS pNt = GetNTHeaders();
	if (pNt->Signature!=IMAGE_NT_SIGNATURE)
	{
		return false;
	}
	return true;
}

PIMAGE_DOS_HEADER CPE::GetDosHeader()
{
	return (PIMAGE_DOS_HEADER)m_buff;
}

PIMAGE_NT_HEADERS CPE::GetNTHeaders()
{
	PIMAGE_DOS_HEADER pDos = GetDosHeader();
	PIMAGE_NT_HEADERS pNt = 
		(PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)m_buff);
	return pNt;
}



PIMAGE_EXPORT_DIRECTORY CPE::GetExportDirectory()
{
	DWORD ExportRva = GetNTHeaders()->OptionalHeader.DataDirectory[0].VirtualAddress;
	DWORD dwOffset = RvaToFoa(ExportRva);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
		(dwOffset + (DWORD)m_buff);
	return pExport;
}

PIMAGE_IMPORT_DESCRIPTOR CPE::GetImportDescriptor()
{
	PIMAGE_NT_HEADERS pNt = GetNTHeaders();
	DWORD ImportRva = pNt->OptionalHeader.DataDirectory[1].VirtualAddress;
	DWORD dwOffset = RvaToFoa(ImportRva);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)
		(dwOffset + (DWORD)m_buff);
	return pImport;
}





DWORD CPE::RvaToFoa(DWORD dwRva)
{
	DWORD offset = 0;
	//1.�ж����RVA�����ĸ�����
	PIMAGE_NT_HEADERS pNt = GetNTHeaders();
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	DWORD dwSectionCount = GetNTHeaders()->FileHeader.NumberOfSections;

	for (int i = 0; i < dwSectionCount; ++i)
	{
		if (dwRva>=pSection[i].VirtualAddress
			&& dwRva<(pSection[i].SizeOfRawData+pSection[i].VirtualAddress))
		{
			//2.�����ҵ�����ݹ�ʽ����
			offset = dwRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
		}
	}
	return offset;
}

void CPE::ShowExportInfo()
{
	if (GetNTHeaders()->OptionalHeader.DataDirectory[0].Size == 0)
	{
		printf("û�е�������Ϣ\n");
		return;
	}
	PIMAGE_EXPORT_DIRECTORY pExport = GetExportDirectory();
	
	//dll����
	char* pDllName = (char*)(RvaToFoa(pExport->Name) + (DWORD)m_buff);
	printf("%s\n", pDllName);
	//������ַ��
	DWORD* pEAT = (DWORD*)(RvaToFoa(pExport->AddressOfFunctions) + (DWORD)m_buff);
	//�������Ʊ�
	DWORD* pENT = (DWORD*)(RvaToFoa(pExport->AddressOfNames) + (DWORD)m_buff);
	//������ű�,Ԫ����WORD
	WORD* pEOT = (WORD*)(RvaToFoa(pExport->AddressOfNameOrdinals) + (DWORD)m_buff);
	//������ַ��ĸ���
	DWORD dwAddrCount = pExport->NumberOfFunctions;
	//�������Ʊ�ĸ���
	DWORD dwNameCount = pExport->NumberOfNames;

	//������ַ��
	for (int i=0;i<dwAddrCount;++i)
	{
		printf("���:%d\t", i + pExport->Base);
		//�������Ʊ�
		for (int j=0;j<dwNameCount;++j)
		{
			//��ַ������==��ű�����ݣ�˵���������������
			if (i==pEOT[j])
			{
				char* pFunName = (char*)
					(RvaToFoa(pENT[j]) + (DWORD)m_buff);
				printf("%s", pFunName);
				break;
			}
		}
		printf("\n");
	}
}

void CPE::ShowImportInfo()
{
	PIMAGE_IMPORT_DESCRIPTOR pImport = GetImportDescriptor();
	//�����ṹ��������0��β
	while (pImport->Name)
	{
		char* pImportName = (char*)
			(RvaToFoa(pImport->Name) + (DWORD)m_buff);
		printf("%s\n", pImportName);

		//��ȡIAT�ĵ�ַ
		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)
			(RvaToFoa(pImport->FirstThunk) + (DWORD)m_buff);
		//����IAT�еĺ���
		while (pIAT->u1.Ordinal)
		{
			//�ж������Ƶ��뻹�ǽ���ŵ���
			if (pIAT->u1.Ordinal&0x80000000)//���λ��1������ŵ���
			{
				printf("���:%d\n", pIAT->u1.Function & 0x7FFFFFFFF);
			}
			else//���λ0�����Ƶ��룬ǰ����ֵ����Ч
			{
				//�ҵ�PIMAGE_IMPORT_BY_NAME�ṹ��ĵ�ַ
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)
					(RvaToFoa(pIAT->u1.AddressOfData) + (DWORD)m_buff);
				printf("���:%08d\t������:%s\n", pName->Hint, pName->Name);
			}
			pIAT++;
		}
		pImport++;
	}
}

