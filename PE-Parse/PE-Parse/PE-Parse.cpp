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
	printf("Init complete.\n");
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
	if (this->pOptionHead->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) printf("The file can remove\n");
	else printf("the file can not remove.\n");
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
			dwRVA <= this->pSectionHead[i].VirtualAddress + this->pSectionHead[i].Misc.VirtualSize)	//判断在哪个节区中
		{
			dwFOA = this->pSectionHead[i].PointerToRawData + dwRVA - this->pSectionHead[i].VirtualAddress;	//根据节区的偏移算出FOA
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

		printf("The INT Information:\n");	// get INT table
		pINT = (PDWORD)((DWORD)(this->pDosHead) + 
									this->RVAToFOA(this->pImportTable[i].OriginalFirstThunk));
		while (*pINT)
		{
			if (IMAGE_SNAP_BY_ORDINAL32(*pINT)) //the highest bit is 1?
			{
				DWORD dwOrder = *pINT & ~IMAGE_ORDINAL_FLAG32;	//clear highest bit
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


		printf("The IAT Information:\n"); // get IAT table
		pIAT = (PDWORD)((DWORD)(this->pDosHead) + this->RVAToFOA(this->pImportTable[i].FirstThunk));
		while (*pIAT)
		{
			if (IMAGE_SNAP_BY_ORDINAL32(*pIAT))		//the highest bit is 1?
			{
				DWORD dwOrder = *pIAT & ~IMAGE_ORDINAL_FLAG32;	//clear highest bit
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

	//获取dll的名称
	pDllName = (char *)((DWORD)this->pDosHead + this->RVAToFOA(this->pExportTable->Name));
	printf("The Dll name is %s\n", pDllName);


	//获取三个数组地址
	pNameArr = (PDWORD)((DWORD)this->pDosHead + this->RVAToFOA(this->pExportTable->AddressOfNames));
	pOrderArr = (PWORD)((DWORD)this->pDosHead + this->RVAToFOA(this->pExportTable->AddressOfNameOrdinals));
	pFunArr = (PDWORD)((DWORD)this->pDosHead + this->RVAToFOA(this->pExportTable->AddressOfFunctions));

	//获取以名字作为导出函数的个数
	dwNumOfName = this->pExportTable->NumberOfNames;
	
	
	printf("print function address by AddressOfNames\n");
	for (i = 0; i < dwNumOfName; i++)
	{
		pFunName = (char *)this->pDosHead + this->RVAToFOA(pNameArr[i]);	//得到函数名称的地址
		printf("The function name is %s\n", pFunName);
		//根据函数名称的下标到序号表中得到函数数组的索引
		printf("The function address is 0x%X\n", this->RVAToFOA(pFunArr[pOrderArr[i]]));
	}
	
	//获取导出函数的总个数
	dwNumOfFun = this->pExportTable->NumberOfFunctions;
	printf("print function address by AddressOfFunctions\n");
	for (i = 0; i < dwNumOfFun; i++)
	{
		if (pFunArr[i])	//如果不是0，说明里面保存的是函数地址RVA
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

bool PEParse::AddSection()
{
	unsigned char szShellcode[] = {
		 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xF8, 0x00, 0x00, 0x00, 0x53, 0x56, 0x57, 0xC7, 0x45, 0xFC, 0x00,
		 0x00, 0x00, 0x00, 0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x45, 0xDC, 0x4B, 0xC6, 0x45,
		 0xDD, 0x00, 0xC6, 0x45, 0xDE, 0x45, 0xC6, 0x45, 0xDF, 0x00, 0xC6, 0x45, 0xE0, 0x52, 0xC6, 0x45,
		 0xE1, 0x00, 0xC6, 0x45, 0xE2, 0x4E, 0xC6, 0x45, 0xE3, 0x00, 0xC6, 0x45, 0xE4, 0x45, 0xC6, 0x45,
		 0xE5, 0x00, 0xC6, 0x45, 0xE6, 0x4C, 0xC6, 0x45, 0xE7, 0x00, 0xC6, 0x45, 0xE8, 0x33, 0xC6, 0x45,
		 0xE9, 0x00, 0xC6, 0x45, 0xEA, 0x32, 0xC6, 0x45, 0xEB, 0x00, 0xC6, 0x45, 0xEC, 0x2E, 0xC6, 0x45,
		 0xED, 0x00, 0xC6, 0x45, 0xEE, 0x44, 0xC6, 0x45, 0xEF, 0x00, 0xC6, 0x45, 0xF0, 0x4C, 0xC6, 0x45,
		 0xF1, 0x00, 0xC6, 0x45, 0xF2, 0x4C, 0xC6, 0x45, 0xF3, 0x00, 0xC6, 0x45, 0xF4, 0x00, 0xC6, 0x45,
		 0xF5, 0x00, 0xC6, 0x45, 0xCC, 0x47, 0xC6, 0x45, 0xCD, 0x65, 0xC6, 0x45, 0xCE, 0x74, 0xC6, 0x45,
		 0xCF, 0x50, 0xC6, 0x45, 0xD0, 0x72, 0xC6, 0x45, 0xD1, 0x6F, 0xC6, 0x45, 0xD2, 0x63, 0xC6, 0x45,
		 0xD3, 0x41, 0xC6, 0x45, 0xD4, 0x64, 0xC6, 0x45, 0xD5, 0x64, 0xC6, 0x45, 0xD6, 0x72, 0xC6, 0x45,
		 0xD7, 0x65, 0xC6, 0x45, 0xD8, 0x73, 0xC6, 0x45, 0xD9, 0x73, 0xC6, 0x45, 0xDA, 0x00, 0xC6, 0x45,
		 0xBC, 0x4C, 0xC6, 0x45, 0xBD, 0x6F, 0xC6, 0x45, 0xBE, 0x61, 0xC6, 0x45, 0xBF, 0x64, 0xC6, 0x45,
		 0xC0, 0x4C, 0xC6, 0x45, 0xC1, 0x69, 0xC6, 0x45, 0xC2, 0x62, 0xC6, 0x45, 0xC3, 0x72, 0xC6, 0x45,
		 0xC4, 0x61, 0xC6, 0x45, 0xC5, 0x72, 0xC6, 0x45, 0xC6, 0x79, 0xC6, 0x45, 0xC7, 0x41, 0xC6, 0x45,
		 0xC8, 0x00, 0xC6, 0x45, 0xB0, 0x75, 0xC6, 0x45, 0xB1, 0x73, 0xC6, 0x45, 0xB2, 0x65, 0xC6, 0x45,
		 0xB3, 0x72, 0xC6, 0x45, 0xB4, 0x33, 0xC6, 0x45, 0xB5, 0x32, 0xC6, 0x45, 0xB6, 0x2E, 0xC6, 0x45,
		 0xB7, 0x64, 0xC6, 0x45, 0xB8, 0x6C, 0xC6, 0x45, 0xB9, 0x6C, 0xC6, 0x45, 0xBA, 0x00, 0xC6, 0x45,
		 0xA4, 0x4D, 0xC6, 0x45, 0xA5, 0x65, 0xC6, 0x45, 0xA6, 0x73, 0xC6, 0x45, 0xA7, 0x73, 0xC6, 0x45,
		 0xA8, 0x61, 0xC6, 0x45, 0xA9, 0x67, 0xC6, 0x45, 0xAA, 0x65, 0xC6, 0x45, 0xAB, 0x42, 0xC6, 0x45,
		 0xAC, 0x6F, 0xC6, 0x45, 0xAD, 0x78, 0xC6, 0x45, 0xAE, 0x41, 0xC6, 0x45, 0xAF, 0x00, 0xC6, 0x45,
		 0x9C, 0x31, 0xC6, 0x45, 0x9D, 0x39, 0xC6, 0x45, 0x9E, 0x30, 0xC6, 0x45, 0x9F, 0x30, 0xC6, 0x45,
		 0xA0, 0x00, 0xC7, 0x45, 0x88, 0x00, 0x00, 0x00, 0x00, 0x50, 0x51, 0x64, 0xA1, 0x30, 0x00, 0x00,
		 0x00, 0x8B, 0x48, 0x0C, 0x89, 0x4D, 0x98, 0x59, 0x58, 0x8B, 0x45, 0x98, 0x83, 0xC0, 0x14, 0x89,
		 0x45, 0x90, 0x8B, 0x45, 0x90, 0x8B, 0x08, 0x89, 0x4D, 0x8C, 0x8D, 0x45, 0xDC, 0x89, 0x85, 0x7C,
		 0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0x8C, 0x83, 0xE8, 0x08, 0x89, 0x45, 0x94, 0x8B, 0x45, 0x94, 0x8B,
		 0x48, 0x30, 0x89, 0x8D, 0x78, 0xFF, 0xFF, 0xFF, 0xC7, 0x85, 0x74, 0xFF, 0xFF, 0xFF, 0x01, 0x00,
		 0x00, 0x00, 0xC7, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x0F, 0x8B, 0x85,
		 0x70, 0xFF, 0xFF, 0xFF, 0x83, 0xC0, 0x01, 0x89, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x8B, 0x85, 0x70,
		 0xFF, 0xFF, 0xFF, 0x8B, 0x8D, 0x7C, 0xFF, 0xFF, 0xFF, 0x0F, 0xB7, 0x14, 0x41, 0x85, 0xD2, 0x0F,
		 0x84, 0x84, 0x00, 0x00, 0x00, 0x8B, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x8B, 0x8D, 0x78, 0xFF, 0xFF,
		 0xFF, 0x0F, 0xB7, 0x14, 0x41, 0x83, 0xFA, 0x61, 0x7C, 0x30, 0x8B, 0x85, 0x70, 0xFF, 0xFF, 0xFF,
		 0x8B, 0x8D, 0x78, 0xFF, 0xFF, 0xFF, 0x0F, 0xB7, 0x14, 0x41, 0x83, 0xFA, 0x7A, 0x7F, 0x1B, 0x8B,
		 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x8B, 0x8D, 0x78, 0xFF, 0xFF, 0xFF, 0x0F, 0xB7, 0x14, 0x41, 0x83,
		 0xEA, 0x20, 0x89, 0x95, 0x08, 0xFF, 0xFF, 0xFF, 0xEB, 0x16, 0x8B, 0x85, 0x70, 0xFF, 0xFF, 0xFF,
		 0x8B, 0x8D, 0x78, 0xFF, 0xFF, 0xFF, 0x0F, 0xB7, 0x14, 0x41, 0x89, 0x95, 0x08, 0xFF, 0xFF, 0xFF,
		 0x8B, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x8B, 0x8D, 0x7C, 0xFF, 0xFF, 0xFF, 0x0F, 0xB7, 0x14, 0x41,
		 0x3B, 0x95, 0x08, 0xFF, 0xFF, 0xFF, 0x74, 0x0C, 0xC7, 0x85, 0x74, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
		 0x00, 0x00, 0xEB, 0x05, 0xE9, 0x55, 0xFF, 0xFF, 0xFF, 0x8B, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x8B,
		 0x8D, 0x78, 0xFF, 0xFF, 0xFF, 0x0F, 0xB7, 0x14, 0x41, 0x85, 0xD2, 0x74, 0x0A, 0xC7, 0x85, 0x74,
		 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x83, 0xBD, 0x74, 0xFF, 0xFF, 0xFF, 0x00, 0x74, 0x0B,
		 0x8B, 0x45, 0x94, 0x8B, 0x48, 0x18, 0x89, 0x4D, 0xFC, 0xEB, 0x14, 0x8B, 0x45, 0x8C, 0x8B, 0x08,
		 0x89, 0x4D, 0x8C, 0x8B, 0x45, 0x8C, 0x3B, 0x45, 0x90, 0x0F, 0x85, 0xE4, 0xFE, 0xFF, 0xFF, 0x83,
		 0x7D, 0xFC, 0x00, 0x0F, 0x84, 0x79, 0x01, 0x00, 0x00, 0x8B, 0x45, 0xFC, 0x89, 0x85, 0x68, 0xFF,
		 0xFF, 0xFF, 0x8B, 0x85, 0x68, 0xFF, 0xFF, 0xFF, 0x8B, 0x48, 0x3C, 0x8B, 0x95, 0x68, 0xFF, 0xFF,
		 0xFF, 0x8D, 0x44, 0x0A, 0x18, 0x89, 0x85, 0x64, 0xFF, 0xFF, 0xFF, 0xB8, 0x08, 0x00, 0x00, 0x00,
		 0x6B, 0xC8, 0x00, 0x8B, 0x95, 0x64, 0xFF, 0xFF, 0xFF, 0x8B, 0x44, 0x0A, 0x60, 0x03, 0x85, 0x68,
		 0xFF, 0xFF, 0xFF, 0x89, 0x85, 0x60, 0xFF, 0xFF, 0xFF, 0x8B, 0x85, 0x60, 0xFF, 0xFF, 0xFF, 0x8B,
		 0x48, 0x14, 0x89, 0x8D, 0x5C, 0xFF, 0xFF, 0xFF, 0x8B, 0x85, 0x60, 0xFF, 0xFF, 0xFF, 0x8B, 0x8D,
		 0x68, 0xFF, 0xFF, 0xFF, 0x03, 0x48, 0x20, 0x89, 0x8D, 0x58, 0xFF, 0xFF, 0xFF, 0x8B, 0x85, 0x60,
		 0xFF, 0xFF, 0xFF, 0x8B, 0x48, 0x1C, 0x03, 0x4D, 0xFC, 0x89, 0x8D, 0x54, 0xFF, 0xFF, 0xFF, 0x8B,
		 0x85, 0x60, 0xFF, 0xFF, 0xFF, 0x8B, 0x48, 0x24, 0x03, 0x4D, 0xFC, 0x89, 0x8D, 0x50, 0xFF, 0xFF,
		 0xFF, 0xC7, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x0F, 0x8B, 0x85, 0x70,
		 0xFF, 0xFF, 0xFF, 0x83, 0xC0, 0x01, 0x89, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x8B, 0x85, 0x70, 0xFF,
		 0xFF, 0xFF, 0x3B, 0x85, 0x5C, 0xFF, 0xFF, 0xFF, 0x0F, 0x83, 0xC4, 0x00, 0x00, 0x00, 0x8B, 0x85,
		 0x70, 0xFF, 0xFF, 0xFF, 0x8B, 0x8D, 0x58, 0xFF, 0xFF, 0xFF, 0x8B, 0x14, 0x81, 0x03, 0x55, 0xFC,
		 0x89, 0x95, 0x4C, 0xFF, 0xFF, 0xFF, 0xC7, 0x85, 0x74, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00,
		 0xC7, 0x85, 0x6C, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x0F, 0x8B, 0x85, 0x6C, 0xFF,
		 0xFF, 0xFF, 0x83, 0xC0, 0x01, 0x89, 0x85, 0x6C, 0xFF, 0xFF, 0xFF, 0x8B, 0x85, 0x4C, 0xFF, 0xFF,
		 0xFF, 0x03, 0x85, 0x6C, 0xFF, 0xFF, 0xFF, 0x0F, 0xBE, 0x08, 0x85, 0xC9, 0x74, 0x2C, 0x8B, 0x85,
		 0x4C, 0xFF, 0xFF, 0xFF, 0x03, 0x85, 0x6C, 0xFF, 0xFF, 0xFF, 0x0F, 0xBE, 0x08, 0x8B, 0x95, 0x6C,
		 0xFF, 0xFF, 0xFF, 0x0F, 0xBE, 0x44, 0x15, 0xCC, 0x3B, 0xC8, 0x74, 0x0C, 0xC7, 0x85, 0x74, 0xFF,
		 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x02, 0xEB, 0xB2, 0x8B, 0x85, 0x6C, 0xFF, 0xFF, 0xFF,
		 0x0F, 0xBE, 0x4C, 0x05, 0xCC, 0x85, 0xC9, 0x74, 0x0A, 0xC7, 0x85, 0x74, 0xFF, 0xFF, 0xFF, 0x00,
		 0x00, 0x00, 0x00, 0x83, 0xBD, 0x74, 0xFF, 0xFF, 0xFF, 0x00, 0x74, 0x21, 0x8B, 0x85, 0x70, 0xFF,
		 0xFF, 0xFF, 0x8B, 0x8D, 0x50, 0xFF, 0xFF, 0xFF, 0x0F, 0xB7, 0x14, 0x41, 0x8B, 0x85, 0x54, 0xFF,
		 0xFF, 0xFF, 0x8B, 0x0C, 0x90, 0x03, 0x4D, 0xFC, 0x89, 0x4D, 0x88, 0xEB, 0x05, 0xE9, 0x1B, 0xFF,
		 0xFF, 0xFF, 0x83, 0x7D, 0x88, 0x00, 0x74, 0x3B, 0x8D, 0x45, 0xBC, 0x50, 0x8B, 0x4D, 0xFC, 0x51,
		 0xFF, 0x55, 0x88, 0x89, 0x45, 0x84, 0x8D, 0x45, 0xB0, 0x50, 0xFF, 0x55, 0x84, 0x89, 0x45, 0xF8,
		 0x83, 0x7D, 0xF8, 0x00, 0x74, 0x1D, 0x8D, 0x45, 0xA4, 0x50, 0x8B, 0x4D, 0xF8, 0x51, 0xFF, 0x55,
		 0x88, 0x89, 0x45, 0x80, 0x6A, 0x00, 0x8D, 0x45, 0x9C, 0x50, 0x8D, 0x4D, 0x9C, 0x51, 0x6A, 0x00,
		 0xFF, 0x55, 0x80, 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D};
	bool bRes = true;
	DWORD dwFileAlignment = this->pOptionHead->FileAlignment, dwSectionAlignment = this->pOptionHead->SectionAlignment;
	DWORD dwSize = 0;
	void *pDestMemory = NULL;
	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_FILE_HEADER pFileHead = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHead = NULL;
	PIMAGE_SECTION_HEADER pDestSectionHead = NULL;
	HANDLE hFile = NULL;
	DWORD dwRet = 0;
	unsigned char szJmp[5] = { 0xE9, 0, 0, 0, 0 };	//跳转回原位置
	
	if (this->pSectionHead[0].PointerToRawData - 
		((DWORD)&this->pSectionHead[this->pFileHead->NumberOfSections - 1] - (DWORD)this->pDosHead)
		<  2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("间隙不够\n");
		bRes = false;
		goto exit;
	}

	dwSize = this->pSectionHead[this->pFileHead->NumberOfSections - 1].PointerToRawData + this->pSectionHead[this->pFileHead->NumberOfSections - 1].SizeOfRawData + this->Align(sizeof(szShellcode) + sizeof(szJmp), dwFileAlignment);
	pDestMemory = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pDestMemory == NULL)
	{
		this->ShowError("VirtualAlloc");
		bRes = false;
		goto exit;
	}

	ZeroMemory(pDestMemory, dwSize);
	//将原有代码写入
	memcpy(pDestMemory, (void *)this->pDosHead, this->pSectionHead[this->pFileHead->NumberOfSections - 1].PointerToRawData + this->pSectionHead[this->pFileHead->NumberOfSections - 1].SizeOfRawData);

	pDosHead = (PIMAGE_DOS_HEADER)pDestMemory;
	pFileHead = (PIMAGE_FILE_HEADER)((DWORD)pDosHead + pDosHead->e_lfanew + 4);
	pOptionHead = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHead + IMAGE_SIZEOF_FILE_HEADER);
	pDestSectionHead = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHead + pFileHead->SizeOfOptionalHeader);

	//填充执行完ShellCode以后要跳转回去的位置
	*(PDWORD)(szJmp + 1) = this->pOptionHead->AddressOfEntryPoint - (pDestSectionHead[pFileHead->NumberOfSections - 1].VirtualAddress + this->Align(pDestSectionHead[pFileHead->NumberOfSections - 1].Misc.VirtualSize, dwSectionAlignment) + sizeof(szShellcode) + 5);
	
	//将新代码加入
	memcpy((void *)((DWORD)pDestMemory + pDestSectionHead[pFileHead->NumberOfSections - 1].PointerToRawData + pDestSectionHead[pFileHead->NumberOfSections - 1].SizeOfRawData),
			szShellcode, sizeof(szShellcode));
	memcpy((void *)((DWORD)pDestMemory + pDestSectionHead[pFileHead->NumberOfSections - 1].PointerToRawData + pDestSectionHead[pFileHead->NumberOfSections - 1].SizeOfRawData + sizeof(szShellcode)),
			szJmp, sizeof(szJmp));
	//增加节表
	ZeroMemory((void *)&pDestSectionHead[pFileHead->NumberOfSections], IMAGE_SIZEOF_SECTION_HEADER);
	memcpy(pDestSectionHead[pFileHead->NumberOfSections].Name, ".1900", strlen(".1900"));
	pDestSectionHead[pFileHead->NumberOfSections].PointerToRawData = pDestSectionHead[pFileHead->NumberOfSections - 1].PointerToRawData
																+ this->Align(pDestSectionHead[pFileHead->NumberOfSections - 1].SizeOfRawData, dwFileAlignment);
	pDestSectionHead[pFileHead->NumberOfSections].SizeOfRawData = this->Align(sizeof(szShellcode) + sizeof(szJmp), dwFileAlignment);
	pDestSectionHead[pFileHead->NumberOfSections].VirtualAddress = pDestSectionHead[pFileHead->NumberOfSections - 1].VirtualAddress
																+ this->Align(pDestSectionHead[pFileHead->NumberOfSections - 1].Misc.VirtualSize, dwSectionAlignment);
	pDestSectionHead[pFileHead->NumberOfSections].Misc.VirtualSize = this->Align(sizeof(szShellcode) + sizeof(szJmp), dwSectionAlignment);
	pDestSectionHead[pFileHead->NumberOfSections].Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	
	
	pFileHead->NumberOfSections++;	//增加节数量
	pOptionHead->AddressOfEntryPoint = pDestSectionHead[pFileHead->NumberOfSections - 1].VirtualAddress;
	pOptionHead->SizeOfImage += this->Align(sizeof(szShellcode) + sizeof(szJmp), dwSectionAlignment);	//增加SizeOfImage

	hFile = CreateFile( "dest.exe",		//get file handle	//打开目标文件并保存
						GENERIC_READ | GENERIC_WRITE,
						0, NULL,
						CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		this->ShowError("CreateFile");
		bRes = false;
		goto exit;
	}

	if (!WriteFile(hFile, pDestMemory, dwSize, &dwRet, NULL))
	{
		this->ShowError("WriteFile");
		bRes = false;
		goto exit;
	}
exit:
	if (hFile) CloseHandle(hFile);
	if (pDestMemory)
	{
		if (!VirtualFree(pDestMemory, 0, MEM_DECOMMIT))
		{
			this->ShowError("VirtualFree");
		}
	}
	return bRes;
}

DWORD PEParse::Align(DWORD dwSize, DWORD dwAlign)
{
	return dwSize % dwAlign ? dwSize + dwAlign - dwSize % dwAlign : dwSize;
}