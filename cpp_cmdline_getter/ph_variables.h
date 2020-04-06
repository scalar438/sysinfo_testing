#pragma once
#include <Windows.h>

#include "ph_types.h"

extern ULONG WindowsVersion;

extern PVOID PhHeapHandle;

extern PPH_STRING PhSharedEmptyString;

extern PPH_OBJECT_TYPE PhStringType;

extern PPH_OBJECT_TYPE PhObjectTypeObject;

extern SLIST_HEADER PhObjectDeferDeleteListHead;

extern PPH_OBJECT_TYPE PhAllocType;

extern ULONG PhpAutoPoolTlsIndex;

extern ULONG PhObjectTypeCount;

void ph_init();
