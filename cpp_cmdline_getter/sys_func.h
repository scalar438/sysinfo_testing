#pragma once
#include "ph_types.h"
#include <Windows.h>
#include <winnt.h>

NTSYSAPI
NTSTATUS
NTAPI
RtlGetVersion(_Out_ PRTL_OSVERSIONINFOEXW VersionInformation // PRTL_OSVERSIONINFOW
);

_Must_inspect_result_ NTSYSAPI PVOID NTAPI RtlCreateHeap(_In_ ULONG Flags, _In_opt_ PVOID HeapBase,
                                                         _In_opt_ SIZE_T ReserveSize,
                                                         _In_opt_ SIZE_T CommitSize,
                                                         _In_opt_ PVOID Lock,
                                                         _In_opt_ PRTL_HEAP_PARAMETERS Parameters);

NTSYSAPI
PVOID
NTAPI
RtlAllocateHeap(_In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _In_ SIZE_T Size);

NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHeap(_In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _Frees_ptr_opt_ PVOID BaseAddress);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtReadVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                    _Out_writes_bytes_(BufferSize) PVOID Buffer, _In_ SIZE_T BufferSize,
                    _Out_opt_ PSIZE_T NumberOfBytesRead);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass,
                          _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
                          _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength);