// the define of funtion to parse PE structure
#pragma once
#include <Windows.h>
#include <cstdio>

class PEParse
{
public:
	PEParse(char *pFilePath);
	void SetIsPeFile(bool bIsPeFile);	//set check result
	bool GetIsPeFile();					//get check result
	void PrintNtHeadInfo();		//printf NtHead information
	void PrintSectionInfo();	//printf section information

	void PrintImportTable();	//Parse ImportTable
	void PrintExportTable();	//Parse ExportTable
	void PrintRelocationTable();	//Parse RelocationTable

private:
	void *ReadFileBuffer(char *pFilePath);	//read file to memory
	void ShowError(char *pErrMsg);			//to print error message
	bool IsPEFile(void *pFileBuffer);		//check is pe file or not
	DWORD RVAToFOA(DWORD dwRVA);	//convert RVA to FOA
private:
	bool bIsPeFile;	//record is PE file or not
	PIMAGE_DOS_HEADER pDosHead;
	PIMAGE_NT_HEADERS32 pNtFileHead;
	PIMAGE_FILE_HEADER pFileHead;
	PIMAGE_OPTIONAL_HEADER32 pOptionHead;
	PIMAGE_SECTION_HEADER pSectionHead;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable;
	PIMAGE_EXPORT_DIRECTORY pExportTable;
	PIMAGE_BASE_RELOCATION pRelocationTable;
};