#include "PE-Parse.h"

#define FILE_NAME "demo.exe"	//define the exe path to be parsed
#define DLL_NAME "myDll.dll"	//define the dll to be parsed

int main()
{
	PEParse PEObj = PEParse(FILE_NAME);

	if (!PEObj.GetIsPeFile())
	{
		goto exit;
	}

	// PEObj.PrintNtHeadInfo();
	// PEObj.PrintSectionInfo();
	// PEObj.PrintImportTable();
	// PEObj.PrintExportTable();
	// PEObj.PrintRelocationTable();
	if (PEObj.AddSection()) printf("Add Section Successful\n");
exit:
	system("pause");

	return 0;
}