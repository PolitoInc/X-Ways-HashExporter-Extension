#include "pch.h"

#define XWF_PROP_TYPE_PARENT_VOLUME 10
#define XWF_METADATA_APPEND 2

HANDLE hOutputFile = INVALID_HANDLE_VALUE;

LONG XT_Init(DWORD nVersion, DWORD nFlags, HANDLE hMainWnd, struct LicenseInfo* pLicInfo) {
	LONG nResult = 1;

	if (XT_RetrieveFunctionPointers() > 0) {
		// Check that the function pointers we need are available else return -1
		return -1;
	}

	// Check version. We need 19.7 or later.
	if (!(HIWORD(nVersion) >= 19 && LOWORD(nVersion) >= 70)) {
		XWF_OutputMessage(L"Error: X-Ways Forensics v19.7 or greater is required for this plugin.", 0);
		nResult = -1;
	}

	// Get the Case title
	wchar_t szCaseTitle[MAX_PATH], szOutputFileName[MAX_PATH], szCaseDir[MAX_PATH];
	ZeroMemory(szCaseTitle, MAX_PATH);
	ZeroMemory(szOutputFileName, MAX_PATH);
	ZeroMemory(szCaseDir, MAX_PATH);

	INT64 iCaseTitleLen = XWF_GetCaseProp(NULL, XWF_CASEPROP_TITLE, szCaseTitle, MAX_PATH);
	INT64 iCaseDirLen = XWF_GetCaseProp(NULL, XWF_CASEPROP_DIR, szCaseDir, MAX_PATH);

	if (iCaseTitleLen > 0 && iCaseDirLen > 0) {
		StringCchPrintf(szOutputFileName, 1024, L"%s\\%s_Hashes.txt", szCaseDir, szCaseTitle);
		XWF_OutputMessage(szOutputFileName, 0);
	}

	// Initialize the handle to the output file
	hOutputFile = CreateFile(szOutputFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hOutputFile == INVALID_HANDLE_VALUE) {
		XWF_OutputMessage(L"Error opening output file.", 0);
		return -4;	// -4 if you want X-Ways Forensics to stop the whole operation (e.g. volume snapshot refinement) altogether
	}

	// If the file already exists, set the file pointer to the end of the file
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		SetFilePointer(hOutputFile, 0, 0, FILE_END);
	}

	return nResult;	// TODO: If we are thread safe, return 2
}

LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved) {
	MessageBox((HWND)hParentWnd, L"Polito, Inc.\nCopyright 2021\nFile Hash Exporter X-Tension", L"Hash Exporter", MB_OK);
	return 0;
}

LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void* lpReserved) {
	// Notify X-Ways that it should call XT_ProcessItemEx for each item in the volume snapshot
	return XT_PREPARE_CALLPILATE | XT_PREPARE_CALLPI;
}

LONG __stdcall XT_ProcessItemEx(LONG nItemID, HANDLE hItem, void* lpReserved) {
	// Buffer to hold the human-readable hash value
	wchar_t* hashValue = NULL;
	const wchar_t* crLf = L"\r\n";
	int cchHashString = 0;

	// Set the primary hash type to MD5
	INT64 nHashType = XWF_GetVSProp(XWF_VSPROP_HASHTYPE1, NULL); // Requires version 19.7 or higher
	if (nHashType != XWF_HASHTYPE_MD5 &&
		nHashType != XWF_HASHTYPE_SHA1 &&
		nHashType != XWF_HASHTYPE_SHA256) {
		XWF_OutputMessage(L"Unsupported hash type for HASHTYPE1", 0);
		return 0;
	}

	switch (nHashType) {
	case XWF_HASHTYPE_MD5:
		cchHashString = 32 + 1;
		hashValue = (wchar_t*)malloc(cchHashString * sizeof(wchar_t));
		break;
	case XWF_HASHTYPE_SHA1:
		cchHashString = 40 + 1;
		hashValue = (wchar_t*)malloc(cchHashString * sizeof(wchar_t));
		break;
	case XWF_HASHTYPE_SHA256:
		cchHashString = 64 + 1;
		hashValue = (wchar_t*)malloc(cchHashString * sizeof(wchar_t));
		break;
	default:
		break;
	}
	// Get the hash value for this item
	if (hashValue != NULL && cchHashString > 0) {
		ZeroMemory(hashValue, cchHashString * sizeof(wchar_t));
		if (!GetHashString(nItemID, nHashType, hashValue, cchHashString)) {
			XWF_OutputMessage(L"No Hash String for item.", 0);
			return 0;
		}
	}
	
	if (hashValue == NULL) {
		XWF_OutputMessage(L"No hash value returned for item.", 0);
		return 0;
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

LONG __stdcall XT_Done(PVOID lpReserved) {
	if (hOutputFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hOutputFile);
	}
	return 0;
}

// Function to convert the binary hash value to human readable format;
// The provided buffer must be large enough to accommodate the requested hash format otherwise
// this function will return an error code
BOOL GetHashString(LONG nItemID, INT64 hashType, wchar_t* hashBuffer, size_t cchHashBuffer) {
	size_t bufSize = 0;
	BOOL bResult = FALSE;
	BYTE* hashBuf = NULL;
	DWORD dwOperation = 0x01; // Flag to XWF_GetHashValue; See https://www.x-ways.net/forensics/x-tensions/XWF_functions.html#A

	switch (hashType) {
	case 7:
		bufSize = 16;		// MD5
		break;
	case 8:
		bufSize = 20;		// SHA-1
		break;
	case 9:
		bufSize = 32;		// SHA-256
		break;
	default:
		return FALSE;		// Invalid
	}

	if (cchHashBuffer <= (bufSize * 2)) {
		return FALSE;
	}

	// Get the hash value
	hashBuf = (BYTE*)malloc(bufSize);
	if (hashBuf == NULL) {
		return FALSE;
	}

	ZeroMemory(hashBuf, bufSize);
	memcpy(hashBuf, (const void*)&dwOperation, sizeof(DWORD)); // copy the operation to the buffer to tell X-Ways what we're doing
	if (!XWF_GetHashValue(nItemID, hashBuf)) {
		goto cleanup;
	}

	// Copy the values into the provided buffer; first zero the buffer
	ZeroMemory(hashBuffer, cchHashBuffer * sizeof(wchar_t));

	// Convert to human readable string
	size_t n;
	for (n = 0; n < bufSize; ++n) {
		if (SUCCEEDED(StringCchPrintf(&(hashBuffer[n * 2]), cchHashBuffer, L"%02x", (unsigned int)hashBuf[n]))) {
			bResult = TRUE;
		}
	}

cleanup:

	// Free the heap vars
	free(hashBuf);

	return bResult;
}

