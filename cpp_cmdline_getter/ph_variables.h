#pragma once
#include <Windows.h>

#include "ph_types.h"

extern ULONG WindowsVersion;

extern PVOID PhHeapHandle;

extern PPH_STRING PhSharedEmptyString;

extern PPH_OBJECT_TYPE PhStringType;

void ph_init();
