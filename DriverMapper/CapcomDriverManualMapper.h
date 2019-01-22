#pragma once
#include <Windows.h>	
#include "Capcom/MemoryController.h"

class CapcomDriverManualMapper
{
public:
	CapcomDriverManualMapper(const char* ProxyDriverName, const char* DriverName, DWORD64 BaseAddress);
	~CapcomDriverManualMapper();

	void map();
private:
	BYTE* pFileBuffer;
	BYTE* pMappedImage;

	SIZE_T SizeOfImage;
	SIZE_T SizeOfFile;
	DWORD64 BaseAddress;

	wchar_t* mProxyDriverName;

	KernelContext* KrCtx;
	CapcomContext* CpCtx;
	MemoryController Controller;

	FORCEINLINE void FixImports();
	FORCEINLINE void FixRelocation();
	FORCEINLINE BOOL MakePageWritable();

	DWORD64 GetKernelModule(const char* ModuleName);
	DWORD64 GetFunctionAddressByName(DWORD64 Base, const char* Name);
	DWORD64 GetFunctionAddressByOrdinal(DWORD64 Base, UINT16 oridnal);
};

