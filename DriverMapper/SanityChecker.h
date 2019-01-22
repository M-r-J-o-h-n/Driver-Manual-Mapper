#pragma once
#include <vector>

class SanityChecker
{
public:
	SanityChecker(const char* ProxyDriverName, const char* TargetDriverName);
	~SanityChecker();

	bool isBad();
	DWORD64 GetOverwritableSectionOffset();
private:
	struct SECTION_INFO
	{
		DWORD64 SectionBaseOffset;
		SIZE_T SectionSize;
		bool writable;
	};

	BYTE* ProxyDriverFileBuffer;
	std::vector<SECTION_INFO> CodeSectionInfo;

	SIZE_T TagetFileSize;
	SIZE_T ProxyFileSize;
};