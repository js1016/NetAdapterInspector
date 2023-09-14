#include <iostream>
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>

#pragma comment(lib, "wbemuuid.lib")

int main() {
	// Initialize COM.
	HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hr << std::endl;
		return 1;
	}

	// Initialize security.
	hr = CoInitializeSecurity(
		nullptr,
		-1,
		nullptr,
		nullptr,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr,
		EOAC_NONE,
		nullptr
	);
	if (FAILED(hr)) {
		std::cerr << "Failed to initialize security. Error code = 0x" << std::hex << hr << std::endl;
		CoUninitialize();
		return 1;
	}

	// Connect to the root\StandardCimv2 namespace with the current user.
	IWbemLocator* pLoc = nullptr;
	hr = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hr)) {
		std::cerr << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hr << std::endl;
		CoUninitialize();
		return 1;
	}

	IWbemServices* pSvc = nullptr;
	hr = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\StandardCimv2"),
		nullptr,
		nullptr,
		0,
		NULL,
		0,
		0,
		&pSvc
	);
	if (FAILED(hr)) {
		std::cerr << "Could not connect. Error code = 0x" << std::hex << hr << std::endl;
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	// Set the security levels on the WMI connection.
	hr = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		nullptr,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr,
		EOAC_NONE
	);
	if (FAILED(hr)) {
		std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hr << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	// Use the IWbemServices pointer to make a request for all the properties of MSFT_NetAdapter.
	IEnumWbemClassObject* pEnumerator = nullptr;
	hr = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM MSFT_NetAdapter"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&pEnumerator
	);
	if (FAILED(hr)) {
		std::cerr << "Query failed. Error code = 0x" << std::hex << hr << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	// Iterate over the query results.
	IWbemClassObject* pObj = nullptr;
	ULONG uReturn = 0;
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &uReturn);
		if (0 == uReturn) {
			break;
		}

		VARIANT vtProp;
		hr = pObj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY);  // Exclude system properties
		if (FAILED(hr)) {
			std::cerr << "Enumeration failed. Error code = 0x" << std::hex << hr << std::endl;
			break;
		}

		BSTR strName = NULL;
		while (pObj->Next(0, &strName, &vtProp, 0, 0) == WBEM_S_NO_ERROR) {
			if (vtProp.vt == VT_BSTR) {
				wprintf(L"%s : %s\n", strName, vtProp.bstrVal);
			}
			else if (vtProp.vt == VT_NULL) {
				wprintf(L"%s : <NULL>\n", strName);
			}
			else if (vtProp.vt == VT_BOOL) {
				wprintf(L"%s : %s\n", strName, (vtProp.boolVal == VARIANT_TRUE ? L"true" : L"false"));
			}
			else if (vtProp.vt == VT_UI4) {
				wprintf(L"%s : %lu\n", strName, vtProp.ulVal);
			}
			else if (vtProp.vt == VT_I4) {
				wprintf(L"%s : %ld\n", strName, vtProp.lVal);
			}
			else if ((vtProp.vt & VT_ARRAY) && (vtProp.vt & VT_UI4)) {
				SAFEARRAY* sa = vtProp.parray;
				LONG lowerBound, upperBound;
				SafeArrayGetLBound(sa, 1, &lowerBound);
				SafeArrayGetUBound(sa, 1, &upperBound);
				wprintf(L"%s : [", strName);
				for (LONG i = lowerBound; i <= upperBound; i++) {
					ULONG val;
					SafeArrayGetElement(sa, &i, &val);
					wprintf(L"%lu", val);
					if (i < upperBound) {
						wprintf(L", ");
					}
				}
				wprintf(L"]\n");
			}
			else if (vtProp.vt == VT_UI1) {
				wprintf(L"%s : %u\n", strName, vtProp.bVal);
			}
			else if (vtProp.vt == (VT_ARRAY | VT_BSTR)) {
				SAFEARRAY* sa = vtProp.parray;
				LONG lowerBound, upperBound;
				SafeArrayGetLBound(sa, 1, &lowerBound);
				SafeArrayGetUBound(sa, 1, &upperBound);
				wprintf(L"%s : [", strName);
				for (LONG i = lowerBound; i <= upperBound; i++) {
					BSTR val;
					SafeArrayGetElement(sa, &i, &val);
					wprintf(L"\"%s\"", val);
					if (i < upperBound) {
						wprintf(L", ");
					}
					SysFreeString(val);
				}
				wprintf(L"]\n");
			}
			else {
				wprintf(L"%s : <OTHER (VARIANT type %d)>\n", strName, vtProp.vt);
			}
			VariantClear(&vtProp);
			SysFreeString(strName);
		}
		wprintf(L"=======================================\n");
		pObj->Release();
	}

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();
	std::cout << "Press Enter to exit...";
	std::cin.get();
	return 0;
}
