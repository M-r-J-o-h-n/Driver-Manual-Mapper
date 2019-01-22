#include "Loader.h"


#pragma comment(lib, "ntdll.lib")

#define STATUS_SUCCESS 0
#define STATUS_IMAGE_ALREADY_LOADED 0xC000010E

Loader::Loader(CONST LPSTR aDriverName)
{
	string DriverName = aDriverName;
	m_DriverPath = DriverName;

	char buffer[100000] = { 0 }; // Getting absolute path
	GetFullPathNameA(m_DriverPath.c_str(), sizeof(buffer), buffer, NULL);
	m_DriverPath = buffer;
	m_DriverPath.insert(0, "\\??\\");

	for (auto& c : DriverName) {  //xor ;
		c = c ^ 5;
	}
	m_ServiceKey = "System\\CurrentControlSet\\Services\\" + DriverName;
	string DriverReg = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + DriverName;

	cout << aDriverName << " path : " << m_DriverPath << endl;
	cout << aDriverName << " ServiceKey : " << m_ServiceKey << endl;
	cout << aDriverName << " DriverKey : " << DriverReg << endl;

	ANSI_STRING asDriverKey;
	RtlInitAnsiString(&asDriverKey, DriverReg.c_str());          //This does not allocate new string.
	RtlAnsiStringToUnicodeString(&m_uDriverReg, &asDriverKey, TRUE);

	HMODULE hNtdll = GetModuleHandleA("Ntdll.dll");
	NtLoadDriver = (_NtLoadDriver)GetProcAddress(hNtdll, "NtLoadDriver");
	NtUnloadDriver = (_NtLoadDriver)GetProcAddress(hNtdll, "NtUnloadDriver");
}

Loader::~Loader()
{
	RtlFreeUnicodeString(&m_uDriverReg);
}

bool Loader::LoadDriver()
{
	HKEY hKey;
	NTSTATUS ret = -1;

	if (RequirePrivilege(SE_LOAD_DRIVER_NAME) && NtLoadDriver) {
		if (RegCreateKeyA(HKEY_LOCAL_MACHINE, m_ServiceKey.c_str(), &hKey) == ERROR_SUCCESS) {
			DWORD Type = SERVICE_KERNEL_DRIVER;
			RegSetValueExA(hKey, "Type", 0, REG_DWORD, (const BYTE *)&Type, sizeof(DWORD));
			RegSetValueExA(hKey, "ImagePath", 0, REG_SZ, (const BYTE *)m_DriverPath.c_str(), m_DriverPath.size() + 1);
			CloseHandle(hKey);

			ret = NtLoadDriver(&m_uDriverReg);        // LoadDriver
		}
	}
	if (ret == STATUS_IMAGE_ALREADY_LOADED)
	{
		if (UnLoadDriver())
			return LoadDriver();
		else
			return true;
	}
	else if (ret == STATUS_SUCCESS)
	{
		return true;
	}
	else
	{
		cout << "Loading Driver failed CODE : 0x" << hex << ret << dec << endl;
		return false;
	}

	return true;
}

bool Loader::UnLoadDriver()
{
	auto ret = NtUnloadDriver(&m_uDriverReg);
	if (ret)
		cout << "Unloading Driver failed, CODE : 0x" << hex << ret << dec << endl;

	return ret ? false : true;
}

bool Loader::DeleteRegistryKey()
{
	auto ret = RegDeleteKeyA(HKEY_LOCAL_MACHINE, m_ServiceKey.c_str());
	if (ret)
		cout << "Deleting Regkey failed, CODE : 0x" << hex << ret << dec << endl;

	return ret ? false : true;
}

bool Loader::RequirePrivilege(LPCTSTR lpPrivilege)
{
	HANDLE hToken;
	BOOL bErr = FALSE;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	bErr = LookupPrivilegeValue(NULL, lpPrivilege, &luid); // lookup LUID for privilege on local system
	if (bErr != TRUE) {
		return false;
	}
	bErr = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (bErr != TRUE) {
		return false;

	}

	if (ANYSIZE_ARRAY != 1) {
		return false;
	}
	tp.PrivilegeCount = 1; // only adjust one privilege
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	bErr = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	// check GetLastError() to check if privilege has been changed
	if (bErr != TRUE || GetLastError() != ERROR_SUCCESS) {
		return false;
	}
	CloseHandle(hToken);

	return true;
}
