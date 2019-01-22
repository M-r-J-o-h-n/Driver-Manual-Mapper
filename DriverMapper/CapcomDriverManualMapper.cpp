#include <fstream>
#include <assert.h>
#include "CapcomDriverManualMapper.h"
#include "Capcom/KernelRoutines.h"
#include "Capcom/LockedMemory.h"
#include <dbghelp.h>
#include <string>
#include <intrin.h>

using namespace std;

#pragma comment(lib, "Dbghelp.lib") 

#define STATUS_CONFLICTING_ADDRESSES     ((NTSTATUS)0xC0000018L)
#define STATUS_INVALID_IMAGE_FORMAT      ((NTSTATUS)0xC000007BL)

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

CapcomDriverManualMapper::CapcomDriverManualMapper(const char* ProxyDriverName, const char* DriverName, DWORD64 BaseAddress)
	:pFileBuffer(NULL), BaseAddress(BaseAddress)
{
	assert(BaseAddress);

	ifstream driverFile(DriverName, ios::binary | ios::in);
	driverFile.seekg(0, ios::end);

	const auto fileSize = driverFile.tellg();
	driverFile.seekg(0, ios::beg);

	pFileBuffer = new BYTE[fileSize];

	driverFile.read((char*)pFileBuffer, fileSize);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD64)pFileBuffer);
	SizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;
	SizeOfFile = fileSize;

	pMappedImage = new BYTE[SizeOfImage];
	ZeroMemory(pMappedImage, SizeOfImage);

	if (!VirtualLock(pMappedImage, SizeOfImage))
	{
		throw exception("Locking image buffer failed");
	}

	Controller = Mc_InitContext(&CpCtx, &KrCtx);

	if (Controller.CreationStatus)
		throw exception("Controller Raised A Creation Status");

	std::string string_proxy_driver_name = ProxyDriverName;
	auto dot = string_proxy_driver_name.find('.');

	std::wstring wide_string_proxy_driver_name(string_proxy_driver_name.begin(), string_proxy_driver_name.begin() + dot);

	mProxyDriverName = new wchar_t[wide_string_proxy_driver_name.length() + 1];

	memcpy(mProxyDriverName, wide_string_proxy_driver_name.c_str(), (wide_string_proxy_driver_name.length() + 1) * sizeof(WCHAR));

	if (!VirtualLock(mProxyDriverName, (wide_string_proxy_driver_name.length() + 1) * sizeof(WCHAR)))
	{
		throw exception("Locking proxy driver name buffer failed");
	}
}

CapcomDriverManualMapper::~CapcomDriverManualMapper()
{
	static auto invoked = false;

	if (!invoked)
	{
		if (pFileBuffer)
			delete[] pFileBuffer;

		if (pMappedImage)
			delete[] pMappedImage;

		Khk_FreePassiveStub(CpCtx, KrCtx);

		Kr_FreeContext(KrCtx);
		Cl_FreeContext(CpCtx);

		invoked = true;
	}
}

void CapcomDriverManualMapper::map()
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD64)pFileBuffer + pDosHeader->e_lfanew);

	//Fix imports within FILE
	FixImports();

	//Copy header
	memcpy(pMappedImage, pFileBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);

	//Copy section
	for (PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pNtHeader + 1);
		pSection < (PIMAGE_SECTION_HEADER)(pNtHeader + 1) + pNtHeader->FileHeader.NumberOfSections;
		pSection++)
	{
		memcpy((PVOID)(pMappedImage + pSection->VirtualAddress), (PVOID)(pFileBuffer + pSection->PointerToRawData), pSection->SizeOfRawData);
	}

	//Relocate
	FixRelocation();

	//Erase header
	ZeroMemory(pMappedImage, pNtHeader->OptionalHeader.SizeOfHeaders);

	//Change page of code section as writable
	if(!MakePageWritable())
		throw exception("Making page writable has failed");

	NON_PAGED_DATA static auto np_BaseAddress = BaseAddress;
	NON_PAGED_DATA static auto np_SizeOfImage = SizeOfImage;
	NON_PAGED_DATA static auto np_pMappedImage = pMappedImage;
	NON_PAGED_DATA static auto np_ProxyDriverName = mProxyDriverName;
	NON_PAGED_DATA static auto np_EntryPointOffset = pNtHeader->OptionalHeader.AddressOfEntryPoint;
	NON_PAGED_DATA static auto status = STATUS_SUCCESS + 1;

	assert(np_BaseAddress && np_SizeOfImage && np_pMappedImage && np_ProxyDriverName && np_EntryPointOffset);

	/*
	NON_PAGED_DATA static auto KMmCopyMemory = KrCtx->GetProcAddress<fnFreeCall>("MmCopyMemory");
	NON_PAGED_DATA static auto KIoAllocateMdl = KrCtx->GetProcAddress<fnFreeCall>("IoAllocateMdl");
	NON_PAGED_DATA static auto KMmProbeAndLockPages = KrCtx->GetProcAddress<fnFreeCall>("MmProbeAndLockPages");
	NON_PAGED_DATA static auto KMmProtectMdlSystemAddress = KrCtx->GetProcAddress<fnFreeCall>("MmProtectMdlSystemAddress");
	NON_PAGED_DATA static auto KMmMapLockedPages = KrCtx->GetProcAddress<fnFreeCall>("MmMapLockedPages");
	NON_PAGED_DATA static auto KMmUnmapLockedPages = KrCtx->GetProcAddress<fnFreeCall>("MmUnmapLockedPages");
	NON_PAGED_DATA static auto KMmUnlockPages = KrCtx->GetProcAddress<fnFreeCall>("MmUnlockPages");
	NON_PAGED_DATA static auto KIoFreeMdl = KrCtx->GetProcAddress<fnFreeCall>("IoFreeMdl");
	*/

	CpCtx->ExecuteInKernel(NON_PAGED_LAMBDA()
	{
		Np_memcpy(np_BaseAddress, np_pMappedImage, np_SizeOfImage);

		fnFreeCall DriverEntry = (fnFreeCall)(np_BaseAddress + np_EntryPointOffset);
		status = Khk_CallPassive(DriverEntry, np_ProxyDriverName, np_BaseAddress);

		/* DOES NOT WORK, I did this because i wanted to lock np_BaseAddress which is code sectio of proxy driver
		uint64_t mdl = Khk_CallPassive(KIoAllocateMdl, np_BaseAddress, np_SizeOfImage, FALSE, FALSE, NULL);

		if (!mdl)
			break;

		Khk_CallPassive(KMmProbeAndLockPages, mdl, 0, 0);

		uint64_t MdlBase = Khk_CallPassive(KMmMapLockedPages, mdl, 0);

		Khk_CallPassive(KMmProtectMdlSystemAddress, mdl, PAGE_EXECUTE_READWRITE);

		SIZE_T SIZE;
		status = Khk_CallPassive
		(
			KMmCopyMemory,
			MdlBase,
			np_pMappedImage,
			np_SizeOfImage,
			0x2,
			&SIZE
		);

		Khk_CallPassive(KMmUnmapLockedPages, MdlBase, mdl);
		Khk_CallPassive(KMmUnlockPages, mdl);
		Khk_CallPassive(KIoFreeMdl, mdl);


		if (status == STATUS_SUCCESS)
		{
			fnFreeCall DriverEntry = (fnFreeCall)(np_BaseAddress + np_EntryPointOffset);
			status = DriverEntry(np_ProxyDriverName);
		}
		*/
	});

	
	if (status != STATUS_SUCCESS)
	{
		string error = "DriverEntry returned ";
		error += to_string(status);
		throw exception(error.c_str());
	}
}

void CapcomDriverManualMapper::FixImports()
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD64)pFileBuffer + pDosHeader->e_lfanew);

	ULONG size; PIMAGE_SECTION_HEADER pSectionHeader;
	auto pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(pFileBuffer, FALSE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &pSectionHeader);
	
	if (!pImportDesc) {
		assert(GetLastError() == 0);
		return;
	}

	for (; pImportDesc->Name; ++pImportDesc)
	{
		const auto moduleName = (char*)ImageRvaToVa(pNtHeader, pFileBuffer, pImportDesc->Name, NULL);
		const auto moduleBase = GetKernelModule(moduleName);
		if (!moduleBase)
		{
			string error = "Can not find module : ";
			error += moduleName;
			throw exception(error.c_str());
		}

		PIMAGE_THUNK_DATA pThunkData;
		if (pImportDesc->OriginalFirstThunk)
			pThunkData = (PIMAGE_THUNK_DATA)ImageRvaToVa(pNtHeader, pFileBuffer, pImportDesc->OriginalFirstThunk, NULL);
		else
			pThunkData = (PIMAGE_THUNK_DATA)ImageRvaToVa(pNtHeader, pFileBuffer, pImportDesc->FirstThunk, NULL);

		PIMAGE_THUNK_DATA64 pFuncData = (PIMAGE_THUNK_DATA64)ImageRvaToVa(pNtHeader, pFileBuffer, pImportDesc->FirstThunk, NULL);

		assert(pThunkData);
		assert(pFuncData);

		for (; pThunkData->u1.AddressOfData; pThunkData++, pFuncData++)
		{
			DWORD64 FunctionAddress = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(pThunkData->u1.Ordinal))
			{
				const auto ordinal = static_cast<uint16_t>(pThunkData->u1.Ordinal & 0xFFFF);
				FunctionAddress = GetFunctionAddressByOrdinal(moduleBase, ordinal);
			}
			else
			{
				const auto pImport = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(pNtHeader, pFileBuffer, pThunkData->u1.AddressOfData, NULL);
				const auto FuncName = pImport->Name;
				FunctionAddress = GetFunctionAddressByName(moduleBase, FuncName);
			}

			assert(FunctionAddress);

			pFuncData->u1.Function = FunctionAddress;
		}
	}
}

void CapcomDriverManualMapper::FixRelocation()
{
	auto ProcessRelocation = [](uintptr_t image_base_delta, uint16_t data, uint8_t* relocation_base)
	{
#define IMR_RELOFFSET(x)			(x & 0xFFF)

		switch (data >> 12 & 0xF)
		{
		case IMAGE_REL_BASED_HIGH:
		{
			const auto raw_address = reinterpret_cast<int16_t*>(relocation_base + IMR_RELOFFSET(data));
			*raw_address += static_cast<unsigned long>(HIWORD(image_base_delta));
			break;
		}
		case IMAGE_REL_BASED_LOW:
		{
			const auto raw_address = reinterpret_cast<int16_t*>(relocation_base + IMR_RELOFFSET(data));
			*raw_address += static_cast<unsigned long>(LOWORD(image_base_delta));
			break;
		}
		case IMAGE_REL_BASED_HIGHLOW:
		{
			const auto raw_address = reinterpret_cast<size_t*>(relocation_base + IMR_RELOFFSET(data));
			*raw_address += static_cast<size_t>(image_base_delta);
			break;
		}
		case IMAGE_REL_BASED_DIR64:
		{
			auto UNALIGNED raw_address = reinterpret_cast<DWORD_PTR UNALIGNED*>(relocation_base + IMR_RELOFFSET(data));
			*raw_address += image_base_delta;
			break;
		}
		case IMAGE_REL_BASED_ABSOLUTE: // No action required
		case IMAGE_REL_BASED_HIGHADJ: // no action required
		{
			break;
		}
		default:
		{
			throw std::runtime_error("gay relocation!");
			return false;
		}

		}
#undef IMR_RELOFFSET

		return true;
	};

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMappedImage;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD64)pMappedImage + pDosHeader->e_lfanew);

	DWORD64 RelocationDelta = BaseAddress - pNtHeader->OptionalHeader.ImageBase;

	if (RelocationDelta)
	{
		ULONG RelocationSize; PIMAGE_SECTION_HEADER pSectionHeader;
		auto pRelocDir = (PIMAGE_BASE_RELOCATION)ImageDirectoryEntryToDataEx(pMappedImage, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &RelocationSize, &pSectionHeader);

		if (!pRelocDir) {
			assert(GetLastError() == 0);
			return;
		}

		assert(RelocationSize);

		void * relocation_end = reinterpret_cast<uint8_t*>(pRelocDir) + RelocationSize;

		while (pRelocDir < relocation_end)
		{
			auto relocation_base = pMappedImage + pRelocDir->VirtualAddress;

			auto num_relocs = (pRelocDir->SizeOfBlock - 8) >> 1;

			auto relocation_data = reinterpret_cast<PWORD>(pRelocDir + 1);

			for (unsigned long i = 0; i < num_relocs; ++i, ++relocation_data)
			{
				if (ProcessRelocation(RelocationDelta, *relocation_data, (uint8_t*)relocation_base) == FALSE)
				{
					throw exception("failed to relocate!");
					return;
				}
			}

			pRelocDir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocation_data);
		}
	}
}

BOOL CapcomDriverManualMapper::MakePageWritable()
{
	Controller.AttachTo(Controller.FindEProcess(4));

	BOOL Success = TRUE;

	Controller.IterPhysRegion((PVOID)BaseAddress, SizeOfImage, [&](PVOID Va, uint64_t Pa, SIZE_T Sz)
	{
		auto Info = Controller.QueryPageTableInfo(Va);

		if (Info.Pde && Info.Pml4e && Info.Pdpte && Info.Pte)
		{
			if (Info.Pte->present)
			{
				Info.Pte->rw = TRUE;
			}
		}
		else
		{
			Success = FALSE;
		}
	});

	Controller.Detach();

	return Success;
}

DWORD64 CapcomDriverManualMapper::GetKernelModule(const char * ModuleName)
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

DWORD64 CapcomDriverManualMapper::GetFunctionAddressByName(DWORD64 Base, const char * Name)
{
	NON_PAGED_DATA static auto k_RtlFindExportedRoutineByName = KrCtx->GetProcAddress<>("RtlFindExportedRoutineByName");
	NON_PAGED_DATA static DWORD64 address = NULL;
	NON_PAGED_DATA static DWORD64 BaseAddress = NULL;
	NON_PAGED_DATA static const char* name = NULL;

	BaseAddress = Base;
	name = Name;

	CpCtx->ExecuteInKernel(NON_PAGED_LAMBDA()
	{
		address = k_RtlFindExportedRoutineByName(BaseAddress, name);
	});

	return address;
}

DWORD64 CapcomDriverManualMapper::GetFunctionAddressByOrdinal(DWORD64 Base, UINT16 oridnal)
{
	NON_PAGED_DATA static DWORD64 address = NULL;
	NON_PAGED_DATA static DWORD64 BaseAddress = NULL;
	NON_PAGED_DATA static UINT16 Ordinal = NULL;

	BaseAddress = Base;
	Ordinal = oridnal;

	CpCtx->ExecuteInKernel(NON_PAGED_LAMBDA()
	{
		const auto base = BaseAddress;
		const auto ordinal = Ordinal;

		const auto dos_header = (PIMAGE_DOS_HEADER)base;
		const auto nt_headers = (PIMAGE_NT_HEADERS64)(base + dos_header->e_lfanew);
		const auto export_ptr = (PIMAGE_EXPORT_DIRECTORY)(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + base);
		auto address_of_funcs = (PULONG)(export_ptr->AddressOfFunctions + base);
		for (ULONG i = 0; i < export_ptr->NumberOfFunctions; ++i)
		{
			if (export_ptr->Base + (uint16_t)i == ordinal) {
				address = address_of_funcs[i] + base;
				return;
			}
		}
	});

	return address;
}
