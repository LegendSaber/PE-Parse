//the implement of function to parse PE structure
#include "PE-Parse.h"

PEParse::PEParse(char *pFilePath)
{
	void *pFileBuffer = ReadFileBuffer(pFilePath);
	DWORD dwVirtualAddress = 0;

	this->SetIsPeFile(false);	//set false an beginning. If file parse fail, the main.cpp can not run
	if (pFileBuffer == NULL)
	{
		printf("ReadFileBuffer fail\n");
		goto exit;
	}

	if (!this->IsPEFile(pFileBuffer))	//check the file is PE file or not
	{
		printf("this is not pe application!\n");
		goto exit;
	}

	//get file head 
	//this->pFileHead = (PIMAGE_FILE_HEADER)((DWORD)this->pNtFileHead + sizeof(this->pNtFileHead->Signature));
	this->pFileHead = &(this->pNtFileHead->FileHeader); 

	//get optional head
	//this->pOptionHead = (PIMAGE_OPTIONAL_HEADER32)((DWORD)this->pFileHead + IMAGE_SIZEOF_FILE_HEADER);
	this->pOptionHead = &(this->pNtFileHead->OptionalHeader);

	//get section head
	this->pSectionHead = (PIMAGE_SECTION_HEADER)((DWORD)this->pOptionHead + this->pFileHead->SizeOfOptionalHeader);

	//get import table head
	dwVirtualAddress = this->pOptionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (dwVirtualAddress)
	{
		this->pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)this->pDosHead + this->RVAToFOA(dwVirtualAddress));
	}
	else
	{
		this->pImportTable = NULL;
	}
	
	//get export table head
	dwVirtualAddress = this->pOptionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (dwVirtualAddress)
	{
		this->pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)this->pDosHead + this->RVAToFOA(dwVirtualAddress));
	}
	else
	{
		this->pExportTable = NULL;
	}

	//get relocation table head
	dwVirtualAddress = this->pOptionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (dwVirtualAddress)
	{
		this->pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)this->pDosHead + this->RVAToFOA(dwVirtualAddress));
	}
	else
	{
		this->pRelocationTable = NULL;
	}
exit:
	printf("Init Parse complete.\n");
}

void PEParse::ShowError(char *pErrMsg)
{
	printf("%s Error %d\n", pErrMsg, GetLastError());
}

bool PEParse::IsPEFile(void *pFileBuffer)	
{
	bool bRes = true;
	this->pDosHead = (PIMAGE_DOS_HEADER)pFileBuffer;

	//check e_magic
	if (this->pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
	{
		bRes = false;
	}
	else
	{
		//check Signature
		this->pNtFileHead = (PIMAGE_NT_HEADERS32)((DWORD)pFileBuffer + pDosHead->e_lfanew);
		if (pNtFileHead->Signature != IMAGE_NT_SIGNATURE) bRes = false;
	}

	this->SetIsPeFile(bRes);	//set the check result 
	return bRes;
}

bool PEParse::GetIsPeFile()
{
	return this->bIsPeFile;
}

void PEParse::SetIsPeFile(bool bIsPeFile)
{
	this->bIsPeFile = bIsPeFile;
}

void *PEParse::ReadFileBuffer(char *pFilePath)
{
	void *pFileBuffer = NULL;
	DWORD dwFileSize = 0, dwReadSize = 0;
	HANDLE hFile = CreateFile(pFilePath,		//get file handle
							  GENERIC_READ, 
							  0, NULL, 
		                      OPEN_EXISTING, 
							  FILE_ATTRIBUTE_NORMAL,
							  NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		this->ShowError("CreateFile");
		goto Fail;
	}

	dwFileSize = GetFileSize(hFile, NULL);	//get file size
	if (dwFileSize == INVALID_FILE_SIZE)
	{
		this->ShowError("GetFileSize");
		goto Fail;
	}

	pFileBuffer = VirtualAlloc(NULL, dwFileSize,
							   MEM_RESERVE | MEM_COMMIT,
							   PAGE_READWRITE);	//allocate dwFileSize memory
	if (pFileBuffer == NULL)
	{
		this->ShowError("VirtualAlloc");
		goto Fail;
	}

	ZeroMemory(pFileBuffer, dwFileSize);
	if (!ReadFile(hFile, pFileBuffer, dwFileSize, &dwReadSize, NULL))// read file to memory
	{
		this->ShowError("ReadFile");
		goto Fail;
	}

	goto Success;
Fail:
	if (pFileBuffer)
	{
		VirtualFree(pFileBuffer, 0, MEM_RELEASE);
		pFileBuffer = NULL;
	}
Success:
	if (hFile)	CloseHandle(hFile);

	return pFileBuffer;
}

void PEParse::PrintNtHeadInfo()
{
	printf("====================The NtHeaders Information================\n");

	printf("\n================The FileHead Information==============\n");
	//machine info
	WORD dwMachine = this->pFileHead->Machine;
	if (dwMachine & IMAGE_FILE_MACHINE_I386)	printf("The app can run in Intel 386\n");
	if (dwMachine & IMAGE_FILE_MACHINE_IA64)	printf("The app can run in Intel 64\n");
	if (dwMachine & IMAGE_FILE_MACHINE_AMD64)   printf("The app can rum in AMD 64\n");

	printf("The app have %d sections\n", this->pFileHead->NumberOfSections);
	printf("The size of optional header is 0x%X\n", this->pFileHead->SizeOfOptionalHeader);

	WORD dwFileCharacter = this->pFileHead->Characteristics;
	if (dwFileCharacter & IMAGE_FILE_RELOCS_STRIPPED) printf("The app does not have relocation information.\n");
	if (dwFileCharacter & IMAGE_FILE_EXECUTABLE_IMAGE) printf("The app is executable.\n");
	if (dwFileCharacter & IMAGE_FILE_LARGE_ADDRESS_AWARE) printf("The app can handle the addresss > 2gb.\n");
	if (dwFileCharacter & IMAGE_FILE_32BIT_MACHINE) printf("The app can only run 32 bit machine.\n");
	if (dwFileCharacter & IMAGE_FILE_SYSTEM) printf("The app is system file.\n");
	if (dwFileCharacter & IMAGE_FILE_DLL) printf("The app is dll file.\n");
	printf("================The FileHead Information==============\n");

	printf("\n==========The Optional FileHead Information===========\n");
	WORD dwMagic = this->pOptionHead->Magic;
	if (dwMagic & IMAGE_NT_OPTIONAL_HDR32_MAGIC) printf("The app is PE file in 32 bit\n");
	else if (dwMagic & IMAGE_NT_OPTIONAL_HDR64_MAGIC) printf("The app is PE file in 64 bit\n");
	printf("Address of entrypoint is 0x%X\n", this->pOptionHead->AddressOfEntryPoint);
	printf("Image Base is 0x%X\n", this->pOptionHead->ImageBase);
	printf("Section Alignment Size is 0x%X\n", this->pOptionHead->SectionAlignment);
	printf("File Alignment Size is 0x%X\n", this->pOptionHead->FileAlignment);
	printf("Size of Image is 0x%X\n", this->pOptionHead->SizeOfImage);
	printf("Size of Headers is 0x%X\n", this->pOptionHead->SizeOfHeaders);
	if (this->pOptionHead->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) printf("The file can remove\n");
	else printf("the file can not remove.\n");
	
	WORD dwSubSystem = this->pOptionHead->Subsystem;
	printf("The Subsystem is");
	switch (dwSubSystem)
	{
		case IMAGE_SUBSYSTEM_NATIVE:
			printf(" navite\n");
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:
			printf(" GUI system\n");
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:
			printf(" CUI system(console or dll)\n");
			break;
	}


	printf("==========The Optional FileHead Information===========\n");

	printf("\n====================The NtHeaders Information================\n");
}

void PEParse::PrintSectionInfo()
{
	WORD dwSectionNum = this->pFileHead->NumberOfSections, i = 0, j = 0;
	char szSectionName[10] = { 0 };
	DWORD dwSectionCharacter = 0;

	printf("===================The section information===================\n");
	for (i = 0; i < dwSectionNum; i++)
	{
		for (j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++)
		{
			szSectionName[j] = 0;
			szSectionName[j] = this->pSectionHead[i].Name[j];
		}
		printf("The %d section information:\n", i);
		printf("The section name is %s\n", szSectionName);
		printf("The virtual size of the section is 0x%X\n", this->pSectionHead[i].Misc.VirtualSize);
		printf("The virtual address of the section is 0x%X\n", this->pSectionHead[i].VirtualAddress);
		printf("The section size of raw data is 0x%X\n", this->pSectionHead[i].SizeOfRawData);
		printf("The section pointer to raw data is 0x%X\n", this->pSectionHead[i].PointerToRawData);

		dwSectionCharacter = this->pSectionHead[i].Characteristics;
		if (dwSectionCharacter & IMAGE_SCN_CNT_CODE) printf("The section have code.\n");
		if (dwSectionCharacter & IMAGE_SCN_CNT_INITIALIZED_DATA) printf("The section have initialized data\n");
		if (dwSectionCharacter & IMAGE_SCN_CNT_UNINITIALIZED_DATA) printf("The section have uninitialized data\n");
		if (dwSectionCharacter & IMAGE_SCN_MEM_READ) printf("The section can read\n");
		if (dwSectionCharacter & IMAGE_SCN_MEM_WRITE) printf("The section can write\n");
		if (dwSectionCharacter & IMAGE_SCN_MEM_EXECUTE) printf("The section can execute\n");
		printf("\n");
	}
	printf("\n=================The section information===================\n");
}

DWORD PEParse::RVAToFOA(DWORD dwRVA)
{
	DWORD dwFOA = dwRVA;
	WORD wSectionNum = this->pFileHead->NumberOfSections, i = 0;

	for (i = 0; i < wSectionNum; i++)
	{
		if (this->pSectionHead[i].VirtualAddress <= dwRVA && 
			dwRVA <= this->pSectionHead[i].VirtualAddress + this->pSectionHead[i].Misc.VirtualSize)
		{
			dwFOA = this->pSectionHead[i].PointerToRawData + dwRVA - this->pSectionHead[i].VirtualAddress;
			break;
		}
	}

	return dwFOA;
}

void PEParse::PrintImportTable()
{
	char *pDllName = NULL;
	DWORD i = 0;
	PDWORD pINT = NULL, pIAT = NULL;


	if (this->pImportTable == NULL)
	{
		printf("the file doest have import table\n");
		goto exit;
	}

	printf("=============Import Table Information===============\n");
	while (this->pImportTable[i].OriginalFirstThunk != 0 || 
		   this->pImportTable[i].FirstThunk != 0)
	{
		pDllName = (char *)((DWORD)(this->pDosHead) + this->RVAToFOA(this->pImportTable[i].Name));
		printf("The import Dll name is %s\n", pDllName);

		printf("The INT Information:\n");
		pINT = (PDWORD)((DWORD)(this->pDosHead) + 
									this->RVAToFOA(this->pImportTable[i].OriginalFirstThunk));
		while (*pINT)
		{
			if (*pINT & IMAGE_ORDINAL_FLAG32)
			{
				DWORD dwOrder = *pINT - IMAGE_ORDINAL_FLAG32;
				printf("The function order is %d\n", dwOrder);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pFunName = (PIMAGE_IMPORT_BY_NAME)((DWORD)this->pDosHead +
																this->RVAToFOA(*pINT));
				printf("The function name is %s\n", pFunName->Name);
			}
			pINT++;
		}


		printf("The IAT Information:\n");
		pIAT = (PDWORD)((DWORD)(this->pDosHead) + this->RVAToFOA(this->pImportTable[i].FirstThunk));
		while (*pIAT)
		{
			if (*pIAT & 0x80000000)
			{
				DWORD dwOrder = *pIAT - 0x80000000;
				printf("The function order is %d\n", dwOrder);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pFunName = (PIMAGE_IMPORT_BY_NAME)((DWORD)this->pDosHead +
																	this->RVAToFOA(*pIAT));
				printf("The function name is %s\n", pFunName->Name);
			}
			pIAT++;
		}
		i++;
		printf("\n");
	}
	printf("=============Import Table Information===============\n");

exit:;

}

void PEParse::PrintExportTable()
{
	char *pDllName = NULL, *pFunName = NULL;
	DWORD dwNumOfFun = 0, dwNumOfName = 0, i = 0;
	PDWORD pNameArr = NULL, pFunArr = NULL;
	PWORD pOrderArr = NULL;

	if (this->pExportTable == NULL)
	{
		printf("The file does not have export file.\n");
		goto exit;
	}

	printf("=========================The Export Information==========================");

	pDllName = (char *)((DWORD)this->pDosHead + this->RVAToFOA(this->pExportTable->Name));
	printf("The Dll name is %s\n", pDllName);

	pNameArr = (PDWORD)((DWORD)this->pDosHead + this->RVAToFOA(this->pExportTable->AddressOfNames));
	pOrderArr = (PWORD)((DWORD)this->pDosHead + this->RVAToFOA(this->pExportTable->AddressOfNameOrdinals));
	pFunArr = (PDWORD)((DWORD)this->pDosHead + this->RVAToFOA(this->pExportTable->AddressOfFunctions));
	dwNumOfName = this->pExportTable->NumberOfNames;
	
	
	printf("print function address by AddressOfNames\n");
	for (i = 0; i < dwNumOfName; i++)
	{
		pFunName = (char *)this->pDosHead + this->RVAToFOA(pNameArr[i]);
		printf("The function name is %s\n", pFunName);
		printf("The function address is 0x%X\n", this->RVAToFOA(pFunArr[pOrderArr[i]]));
	}

	dwNumOfFun = this->pExportTable->NumberOfFunctions;
	printf("print function address by AddressOfFunctions\n");
	for (i = 0; i < dwNumOfFun; i++)
	{
		if (pFunArr[i])
		{
			printf("The function address is 0x%X\n", this->RVAToFOA(pFunArr[i]));
		}
	}

	printf("=========================The Export Information==========================\n");
exit:;
}

void PEParse::PrintRelocationTable()
{
	PIMAGE_BASE_RELOCATION pRelocationTable = this->pRelocationTable;
	DWORD dwSizeOfBlock = 0, i = 0, dwVirtualAddress = 0, dwNum = 0;
	PWORD pAddr = NULL;

	if (pRelocationTable == NULL)
	{
		printf("The file does not have relocation table.\n");
		goto exit;
	}

	printf("==================The relocation table information===================\n");
	while (pRelocationTable->VirtualAddress != 0 || pRelocationTable->SizeOfBlock != 0)
	{
		dwVirtualAddress = pRelocationTable->VirtualAddress;
		dwSizeOfBlock = pRelocationTable->SizeOfBlock;
		dwNum = (dwSizeOfBlock - 2 * sizeof(DWORD)) / 2;
		pAddr = (PWORD)((DWORD)pRelocationTable + 8);
		for (i = 0; i < dwNum; i++)
		{
			if (pAddr[i] & 0x3000)
			{
				printf("The address of need to be relocation: 0x%X\n", this->RVAToFOA(dwVirtualAddress + (pAddr[i] & 0x0FFF)));
			}
		}
		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + dwSizeOfBlock);
	}
	printf("==================The relocation table information===================\n");
exit:;
}