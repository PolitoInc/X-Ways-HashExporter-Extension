#pragma once

#define XWF_HASHTYPE_MD5	7
#define XWF_HASHTYPE_SHA1	8
#define XWF_HASHTYPE_SHA256 9

#define XWF_CASEPROP_DIR	6

BOOL GetHashString(LONG nItemID, INT64 hashType, wchar_t* hashBuffer, size_t cchHashBuffer);