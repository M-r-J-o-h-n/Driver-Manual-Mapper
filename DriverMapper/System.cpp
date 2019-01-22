#include "System.h"
#include <TlHelp32.h>
#include <vector>
#include <assert.h>
#include "Capcom/NtDefines.h"

DWORD64 GetSystemModuleBaseAddress(const char* ModuleName)
{
	ULONG ReqSize = 0;
	std::vector<BYTE> Buffer(1024 * 1024);

	do
	{
		if (!NtQuerySystemInformation(SystemModuleInformation, Buffer.data(), Buffer.size(), &ReqSize))
			break;

		Buffer.resize(ReqSize * 2);
	} while (ReqSize > Buffer.size());

	SYSTEM_MODULE_INFORMATION* ModuleInfo = (SYSTEM_MODULE_INFORMATION*)Buffer.data();

	for (size_t i = 0; i < ModuleInfo->Count; ++i)
	{
		char* KernelFileName = (char*)ModuleInfo->Module[i].FullPathName + ModuleInfo->Module[i].OffsetToFileName;
		if (!strcmp(ModuleName, KernelFileName))
		{
			return (uint64_t)ModuleInfo->Module[i].ImageBase;
		}
	}

	return 0;
}

