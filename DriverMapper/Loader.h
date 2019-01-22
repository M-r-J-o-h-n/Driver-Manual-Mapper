#pragma once
#include <Windows.h>
#include <SDKDDKVer.h>

#include <stdio.h>
#include <tchar.h>

#include <iostream>

#include <Winternl.h>
#include <string>

using namespace std;


typedef NTSTATUS(*_NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);


class Loader
{
public:
	Loader(CONST LPSTR aDriverName);
	~Loader();

	bool LoadDriver();
	bool UnLoadDriver();
	bool DeleteRegistryKey();
private:
	bool RequirePrivilege(LPCTSTR lpPrivilege);

	string m_DriverPath;
	string m_ServiceKey;
	UNICODE_STRING m_uDriverReg;

	_NtLoadDriver NtLoadDriver;
	_NtLoadDriver NtUnloadDriver;
};

