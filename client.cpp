#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_DCOM
#define UNICODE

#include <iostream>
#include <comutil.h>
#include <atlbase.h>
#include <tchar.h>
#include <Wbemidl.h>
#include <vector>
#include <comdef.h>
#include <wincred.h>
#include <strsafe.h>
#include "structures.h"

#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "credui.lib")

using namespace std;

IWbemLocator *pLoc = NULL;
IWbemServices *pSvc = NULL;

wchar_t ipAddr[CREDUI_MAX_USERNAME_LENGTH + 1];
wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = { 0 };
wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH + 1];
wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH + 1];
wchar_t pszAuthority[CREDUI_MAX_USERNAME_LENGTH + 1];

COAUTHIDENTITY *userAcct = NULL;
COAUTHIDENTITY authIdent;

void unInitialize()
{
	if (pSvc != NULL)
	{
		pSvc->Release();
		pSvc = NULL;
	}

	if (pLoc != NULL)
	{
		pLoc->Release();
		pLoc = NULL;
	}
}

wstring WmiQueryValue(IWbemClassObject* pclsObj, LPCWSTR szName)
{
	wstring value = L"0";

	if (pclsObj != NULL && szName != NULL)
	{
		VARIANT vtProp;

		HRESULT hr = pclsObj->Get(szName, 0, &vtProp, 0, 0);
		if (SUCCEEDED(hr))
		{
			if (vtProp.vt == VT_BSTR && ::SysStringLen(vtProp.bstrVal) > 0)
			{
				value = vtProp.bstrVal;
			}
			else
			{
				value = std::to_wstring(vtProp.intVal);
			}
		}
	}

	return value;
}

void WmiGetSpecialValues(PRODUCT* el, IWbemClassObject* pclsObj)
{
	//wcout << L"Name: " << WmiQueryValue(pclsObj, L"Name") << endl;
	wcout << L"ID: " << WmiQueryValue(pclsObj, L"IdentifyingNumber") << endl;
	wcout << L"Version: " << WmiQueryValue(pclsObj, L"Version") << endl;
	wcout << L"Vendor: " << WmiQueryValue(pclsObj, L"Vendor") << endl;
}

void WmiGetSpecialValues(PROCESS* el, IWbemClassObject* pclsObj)
{
	wcout << L"Caption: " << WmiQueryValue(pclsObj, L"Caption") << endl;
	wcout << L"ProcessId: " << WmiQueryValue(pclsObj, L"ProcessId") << endl;
	wcout << L"ExecutablePath: " << WmiQueryValue(pclsObj, L"ExecutablePath") << endl;
	wcout << L"HandleCount: " << WmiQueryValue(pclsObj, L"HandleCount") << endl;
}

void WmiGetSpecialValues(SERVICE* el, IWbemClassObject* pclsObj)
{
	wcout << L"Name: " << WmiQueryValue(pclsObj, L"Name") << endl;
	wcout << L"ProcessId: " << WmiQueryValue(pclsObj, L"ProcessId") << endl;
	wcout << L"StartMode: " << WmiQueryValue(pclsObj, L"StartMode") << endl;
	wcout << L"State: " << WmiQueryValue(pclsObj, L"State") << endl;
	wcout << L"Status: " << WmiQueryValue(pclsObj, L"Status") << endl;
}

void WmiGetSpecialValues(LOGICALDISK* el, IWbemClassObject* pclsObj)
{
	wcout << L"DeviceId: " << WmiQueryValue(pclsObj, L"DeviceId") << endl;
	wcout << L"DriveType: " << WmiQueryValue(pclsObj, L"DriveType") << endl;
	wcout << L"FreeSpace: " << WmiQueryValue(pclsObj, L"FreeSpace") << endl;
	wcout << L"Size: " << WmiQueryValue(pclsObj, L"Size") << endl;
}

void WmiGetSpecialValues(PROCESSOR* el, IWbemClassObject* pclsObj)
{
	wcout << L"Caption: " << WmiQueryValue(pclsObj, L"Caption") << endl;
	wcout<<L"DeviceId: " << WmiQueryValue(pclsObj, L"DeviceId") << endl;
	wcout<<L"Manufacturer: " << WmiQueryValue(pclsObj, L"Manufacturer") << endl;
	wcout<<L"MaxClockSpeed: " << WmiQueryValue(pclsObj, L"MaxClockSpeed") << endl;
	wcout<<L"Name: " << WmiQueryValue(pclsObj, L"Name") << endl;
	wcout<<L"SochetDesignation: " << WmiQueryValue(pclsObj, L"SocketDesignation") << endl;
}

void WmiGetSpecialValues(BIOS* el, IWbemClassObject* pclsObj)
{
	wcout<<L"SMBIOSBIOSVersion: " << WmiQueryValue(pclsObj, L"SMBIOSBIOSVersion") << endl;
	wcout<<L"Manufacturer: " << WmiQueryValue(pclsObj, L"Manufacturer") << endl;
	wcout<<L"Name: " << WmiQueryValue(pclsObj, L"Name") << endl;
	wcout<<L"SerialNumber: " << WmiQueryValue(pclsObj, L"SerialNumber") << endl;
	wcout<<L"Version: " << WmiQueryValue(pclsObj, L"Version") << endl;
}

void WmiGetSpecialValues(HARDDRIVE* el, IWbemClassObject* pclsObj)
{
	wcout << L"Partitions: " << WmiQueryValue(pclsObj, L"Partitions") << endl;
	wcout << L"DeviceId: " << WmiQueryValue(pclsObj, L"DeviceId") << endl;
	wcout << L"Model: " << WmiQueryValue(pclsObj, L"Model") << endl;
	wcout << L"Size: " << WmiQueryValue(pclsObj, L"Size") << endl;
	wcout << L"Caption: " << WmiQueryValue(pclsObj, L"Caption") << endl;
}

void WmiGetSpecialValues(OS* el, IWbemClassObject* pclsObj)
{
	wcout << L"SystemDirectory: " << WmiQueryValue(pclsObj, L"SystemDirectory") << endl;
	wcout << L"BuildNumber: " << WmiQueryValue(pclsObj, L"BuildNumber") << endl;
	wcout << L"RegisteredUser: " << WmiQueryValue(pclsObj, L"RegisteredUser") << endl;
	wcout << L"SerialNumber: " << WmiQueryValue(pclsObj, L"SerialNumber") << endl;
	wcout << L"Version: " << WmiQueryValue(pclsObj, L"Version") << endl;
}

void WmiGetSpecialValues(FIREWALL* el, IWbemClassObject* pclsObj)
{
	wcout << L"InstanceGuid: " << WmiQueryValue(pclsObj, L"InstanceGuid") << endl;
	wcout << L"PathToSignedProductExe: " << WmiQueryValue(pclsObj, L"PathToSignedProductExe") << endl;
	wcout << L"TimeStamp: " << WmiQueryValue(pclsObj, L"TimeStamp") << endl;
}

void WmiGetSpecialValues(ANTIPRODUCT* el, IWbemClassObject* pclsObj)
{
	wcout << L"DisplayName: " << WmiQueryValue(pclsObj, L"DisplayName") << endl;
	wcout << L"InstanceGuid: " << WmiQueryValue(pclsObj, L"InstanceGuid") << endl;
	wcout << L"PathToSignedProductExe: " << WmiQueryValue(pclsObj, L"PathToSignedProductExe") << endl;
	wcout << L"TimeStamp: " << WmiQueryValue(pclsObj, L"TimeStamp") << endl;
}

template<typename T>
void WmiGetInfo(PWCHAR init, PCHAR value)
{
	wchar_t s[CREDUI_MAX_USERNAME_LENGTH + 1];

	wsprintf(s, L"\\\\%ws\\%ws", ipAddr, init);

	HRESULT hres;

	// Obtain the initial locator to WMI
	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);
	if (FAILED(hres))
	{
		cout << "Failed to create IWbemLocator object." << " Err code = 0x" << hex << hres << endl;
		CoUninitialize();
		return;
	}

	// Connect to WMI through the IWbemLocator::ConnectServer method
	hres = pLoc->ConnectServer(_bstr_t(s), _bstr_t(pszName), _bstr_t(pszPwd),
		NULL, NULL, NULL, NULL, &pSvc);
	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x" << hex << hres << endl;
		pLoc->Release();
		CoUninitialize();
		return;
	}

	memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
	authIdent.PasswordLength = wcslen(pszPwd);
	authIdent.Password = (USHORT*)pszPwd;

	LPWSTR slash = wcschr(pszName, L'\\');
	if (slash == NULL)
	{
		cout << "Could not create Auth identity. No domain specified\n";
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
	authIdent.User = (USHORT*)pszUserName;
	authIdent.UserLength = wcslen(pszUserName);

	StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName, slash - pszName);
	authIdent.Domain = (USHORT*)pszDomain;
	authIdent.DomainLength = slash - pszName;
	authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

	userAcct = &authIdent;

	// Set security levels on a WMI connection
	hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, userAcct, EOAC_NONE);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket. Error code = 0x" << hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(value), WBEM_FLAG_FORWARD_ONLY
		| WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

	if (FAILED(hres))
	{
		cout << "Query for name failed." << " Error code = 0x" << hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	hres = CoSetProxyBlanket(pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, userAcct, EOAC_NONE);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket on enumerator. Error code = 0x" << hex << hres << endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	// Get the data from the query
	IWbemClassObject* pclsObj;
	ULONG uReturn = 0;
	T el;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (!uReturn)
		{
			break;
		}

		WmiGetSpecialValues(&el, pclsObj);
		wcout << endl;

		pclsObj->Release();

	}

	pEnumerator->Release();
	unInitialize();
}

int __cdecl main(int argc, char **argv)
{
	HRESULT hres;

	// Initialize COM.
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		cout << "Failed to initialize COM library. Error code = 0x"
			<< hex << hres << endl;
		return 1;
	}

	// Set general COM security levels
	hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IDENTIFY, NULL, EOAC_NONE, NULL);
	if (FAILED(hres))
	{
		cout << "Failed to initialize security. Error code = 0x" << hex << hres << endl;
		CoUninitialize();
		return 1;
	}

	// Get the user name and password for the remote computer
	cout << "Target IP address: ";
	wcin >> ipAddr;
	cout << "Remote user name: ";
	wcin >> pszName;
	cout << "Remote user password: ";
	wcin >> pszPwd;

	/*wcscpy(ipAddr, L"192.168.79.129");
	wcscpy(pszName, L"DESKTOP-J7GNUSB\\mrale");
	wcscpy(pszPwd, L"1234");*/

	//StringCchPrintf(pszAuthority, CREDUI_MAX_USERNAME_LENGTH + 1, L"kERBEROS:%s", pszNamePC);

	int command, f = 1;
	printf("1 - enum products\n2 - enum processes\n3 - enum services\n\
4 - enum logical disks\n5 - processor information\n\
6 - BIOS information\n7 - hard drive information\n8 - OS information\n\
9 - firewall information\n10 - antivirus information\n11 - spyware information\n\
0 - exit\n\n");

	while (f)
	{
		printf(">> ");
		scanf("%d", &command);
		switch (command)
		{
		case 0: f = 0; break;
		case 1: WmiGetInfo<PRODUCT>(L"root\\cimv2", "Select * from Win32_Product"); break;
		case 2: WmiGetInfo<PROCESS>(L"root\\cimv2", "Select * from Win32_Process"); break;
		case 3: WmiGetInfo<SERVICE>(L"root\\cimv2", "Select * from Win32_Service"); break;
		case 4: WmiGetInfo<LOGICALDISK>(L"root\\cimv2", "Select * from Win32_LogicalDisk"); break;
		case 5: WmiGetInfo<PROCESSOR>(L"root\\cimv2", "Select * from Win32_Processor"); break;
		case 6: WmiGetInfo<BIOS>(L"root\\cimv2", "Select * from Win32_Bios"); break;
		case 7: WmiGetInfo<HARDDRIVE>(L"root\\cimv2", "Select * from Win32_DiskDrive"); break;
		case 8: WmiGetInfo<OS>(L"root\\cimv2", "Select * from Win32_OperatingSystem"); break;
		case 9: WmiGetInfo<FIREWALL>(L"root\\SecurityCenter2", "Select * from FirewallProduct"); break;
		case 10: WmiGetInfo<ANTIPRODUCT>(L"root\\SecurityCenter2", "Select * from AntiVirusProduct"); break;
		case 11: WmiGetInfo<ANTIPRODUCT>(L"root\\SecurityCenter2", "Select * from AntiSpywareProduct"); break;
		default: break;
		}
	}

	SecureZeroMemory(pszName, sizeof(pszName));
	SecureZeroMemory(pszPwd, sizeof(pszPwd));
	SecureZeroMemory(pszUserName, sizeof(pszUserName));
	SecureZeroMemory(pszDomain, sizeof(pszDomain));

	CoUninitialize();

	return 0;
}