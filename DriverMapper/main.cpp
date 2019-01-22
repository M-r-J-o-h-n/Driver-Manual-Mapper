#include <iostream>
#include <assert.h>
#include "Loader.h"
#include "System.h"
#include "CapcomDriverManualMapper.h"
#include "SanityChecker.h"

using namespace std;

int main(const int argc, char** argv)
{
	if (argc != 3)
		throw exception("Number of parameters are less than required");
	
	const char* ProxyDriverName = argv[1];
	const char* TargetDriverName = argv[2];

	CapcomDriverManualMapper* mapper;

	try
	{
		SanityChecker* checker = new SanityChecker(ProxyDriverName, TargetDriverName);

		Loader ProxyDriverLoader((CONST LPSTR)ProxyDriverName);

		if (!ProxyDriverLoader.LoadDriver())
		{
			string error = "Loading "; error += ProxyDriverName; error += " failed";
			throw exception(error.c_str());
		}

		ProxyDriverLoader.DeleteRegistryKey();

		auto ProxyDriverModuleBase = GetSystemModuleBaseAddress(ProxyDriverName);
		assert(ProxyDriverModuleBase);

		cout << "Mapping Driver..." << endl;

		mapper = new CapcomDriverManualMapper(ProxyDriverName, TargetDriverName, ProxyDriverModuleBase + checker->GetOverwritableSectionOffset());
		mapper->map();

		cout << TargetDriverName << " successfully was mapped" << endl;
	}
	catch (exception ex)
	{
		cout << "Exception Occured -> " << ex.what() << endl;
	}
	mapper->~CapcomDriverManualMapper();
	getchar();
	return 0;
}