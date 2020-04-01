/* This file contains functions that I didn't found in the PH */
#include <Windows.h>
#include <winnt.h>


BOOLEAN
NTAPI
RtlFreeHeap(_In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _Frees_ptr_opt_ PVOID BaseAddress)
{
	throw 42;
}