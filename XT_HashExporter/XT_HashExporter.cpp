#include "pch.h"

#define XWF_PROP_TYPE_PARENT_VOLUME 10
#define XWF_METADATA_APPEND 2

HANDLE hOutputFile = INVALID_HANDLE_VALUE;

LONG XT_Init(DWORD nVersion, DWORD nFlags, HANDLE hMainWnd, struct LicenseInfo* pLicInfo) {
	if (XT_RetrieveFunctionPointers() > 0) {
		// Check that the function pointers we need are available else return -1
		return -1;
	}

	return 1;	// TODO: If we are thread safe, return 2
}

LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved) {
	MessageBox((HWND)hParentWnd, L"Polito, Inc.\nCopyright 2021\nFile Hash Exporter X-Tension", L"Hash Exporter", MB_OK);
	return 0;
}

LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void* lpReserved) {
	// TODO: Check version. We need 17.4 or later.
	
	// Get the Case title
	wchar_t szCaseTitle[1024], szOutputFileName[1024];
	ZeroMemory(szCaseTitle, 1024);
	ZeroMemory(szOutputFileName, 1024);
	INT64 iCaseTitleLen = XWF_GetCaseProp(NULL, XWF_CASEPROP_TITLE, szCaseTitle, 1024);

	if (iCaseTitleLen > 0) {
		if (FAILED(StringCchPrintf(szOutputFileName, 1024, L"%s_Hashes.txt", szCaseTitle))) {
			StringCchPrintf(szOutputFileName, 1024, L"UnknownCase_Hashes.txt");
		}
	}
	else {
		StringCchPrintf(szOutputFileName, 1024, L"UnknownCase_Hashes.txt");
	}

	// Set the primary hash type to MD5
	BYTE hashType = 0x7;
	INT64 nSetHashTypeResult = XWF_GetVSProp(XWF_VSPROP_SET_HASHTYPE1, &hashType);
	if (nSetHashTypeResult < 0) {
		XWF_OutputMessage(L"Error computing hash value for evidence item.", 0);
		return NULL;
	}

	// Initialize the handle to the output file
	hOutputFile = CreateFile(szOutputFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hOutputFile == INVALID_HANDLE_VALUE) {
		return -4;	// -4 if you want X-Ways Forensics to stop the whole operation (e.g. volume snapshot refinement) altogether
	}

	// If the file already exists, set the file pointer to the end of the file
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		SetFilePointer(hOutputFile, 0, 0, FILE_END);
	}

	// Notify X-Ways that it should call XT_ProcessItemEx for each item in the volume snapshot
	return XT_PREPARE_CALLPI;
}

LONG __stdcall XT_ProcessItemEx(LONG nItemID, HANDLE hItem, void* lpReserved) {
	// Get the hash value for this item
	wchar_t* hashValue = GetHashString(nItemID, hItem);
	const wchar_t* crLf = L"\r\n";

	if (hashValue == NULL) {
		return -1;
	}

	// Write the file name and hash value to the output file
	//StringCchPrintf(filenameAndHashBuffer, len, L"%s %s\n", fileName, hashValue);
	DWORD dwNumWritten = 0;
	WriteFile(hOutputFile, hashValue, (DWORD)(wcslen(hashValue) * sizeof(wchar_t)), &dwNumWritten, NULL);
	WriteFile(hOutputFile, crLf, 4, &dwNumWritten, NULL);

	// Free the hash value string
	free(hashValue);

	return 0;
}

LONG __stdcall XT_Finalize(HANDLE hVolume, HANDLE hEvidence, DWORD nOptType, PVOID lpReserved) {
	if (hOutputFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hOutputFile);
	}
	return 0;
}

// Function to convert the binary hash value to human readable format;
// It is the responsibility of the caller to free the hash string when done
wchar_t* GetHashString(LONG nItemID, HANDLE hItem) {
	int bufSize = 16;	// 16 bytes for MD5

	// Get the hash value
	// First, allocate a buffer to hold the hash value
	BYTE* hashBuf = (BYTE*)malloc(bufSize);
	if (hashBuf == NULL) {
		return NULL;
	}

	// Zero out the buffer
	ZeroMemory(hashBuf, bufSize);

	// Copy the required values into the buffer
	DWORD dwOperation = 0x11;	// 0x01 = retrieve primary hash value, 0x10 = compute hash value if not already calculated
	memcpy(hashBuf, (const void*)&dwOperation, sizeof(DWORD));
	memcpy(hashBuf + sizeof(DWORD), &hItem, sizeof(HANDLE));

	// Ask XWF to compute the MD5 hash value and return it to us
	XWF_GetHashValue(nItemID, hashBuf);

	// String to hold the human-readable hash value
	size_t len = (((size_t)bufSize * 2) + 1) * sizeof(wchar_t);
	wchar_t* out = (wchar_t*)malloc(len);

	// Check that our memory allocation succeeded
	if (out == NULL) {
		free(hashBuf);
		return NULL;
	}

	ZeroMemory(out, len);

	// Convert to human readable string
	int n;
	for (n = 0; n < bufSize; ++n) {
		StringCchPrintf(&(out[n * 2]), bufSize * 2, L"%02x", (unsigned int)hashBuf[n]);
	}

	free(hashBuf);

	// return the result
	return out;
}
