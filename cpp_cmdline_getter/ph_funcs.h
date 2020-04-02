#pragma once

#include "ph_types.h"

#include <Windows.h>
#include <winnt.h>


NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHeap(_In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _Frees_ptr_opt_ PVOID BaseAddress);

/**
 * Frees a block of memory allocated with PhAllocate().
 *
 * \param Memory A pointer to a block of memory.
 */
VOID PhFree(_Frees_ptr_opt_ PVOID Memory);

/**
 * Gets a string stored in a process' parameters structure.
 *
 * \param ProcessHandle A handle to a process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ access.
 * \param Offset The string to retrieve.
 * \param String A variable which receives a pointer to the requested string. You must free the
 * string using PhDereferenceObject() when you no longer need it.
 *
 * \retval STATUS_INVALID_PARAMETER_2 An invalid value was specified in the Offset parameter.
 */
NTSTATUS PhGetProcessPebString(_In_ HANDLE ProcessHandle, _In_ PH_PEB_OFFSET Offset,
                               _Out_ PPH_STRING *String);

/**
 * Queries variable-sized information for a process. The function allocates a buffer to contain the
 * information.
 *
 * \param ProcessHandle A handle to a process. The access required depends on the information class
 * specified.
 * \param ProcessInformationClass The information class to retrieve.
 * \param Buffer A variable which receives a pointer to a buffer containing the information. You
 * must free the buffer using PhFree() when you no longer need it.
 */
NTSTATUS PhpQueryProcessVariableSize(_In_ HANDLE ProcessHandle,
                                     _In_ PROCESSINFOCLASS ProcessInformationClass,
                                     _Out_ PVOID *Buffer);

PPH_STRING
PhCreateStringFromUnicodeString(_In_ PUNICODE_STRING UnicodeString);

NTSTATUS PhGetProcessCommandLine(_In_ HANDLE ProcessHandle, _Out_ PPH_STRING *CommandLine);

/**
 * Gets basic information for a process.
 *
 * \param ProcessHandle A handle to a process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION access.
 * \param BasicInformation A variable which receives the information.
 */
NTSTATUS
PhGetProcessBasicInformation(_In_ HANDLE ProcessHandle,
                             _Out_ PPROCESS_BASIC_INFORMATION BasicInformation);

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

/**
 * Obtains a reference to a zero-length string.
 */
PPH_STRING PhReferenceEmptyString(VOID);

/**
 * Creates a string object using a specified length.
 *
 * \param Buffer A null-terminated Unicode string.
 * \param Length The length, in bytes, of the string.
 */
PPH_STRING PhCreateStringEx(_In_opt_ PWCHAR Buffer, _In_ SIZE_T Length);

/**
 * Dereferences the specified object.
 * The object will be freed if its reference count reaches 0.
 *
 * \param Object A pointer to the object to dereference.
 */
VOID PhDereferenceObject(_In_ PVOID Object);

/**
 * Gets a process' WOW64 PEB address.
 *
 * \param ProcessHandle A handle to a process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION access.
 * \param Peb32 A variable which receives the base address of the process' WOW64 PEB. If the process
 * is 64-bit, the variable receives NULL.
 */
NTSTATUS
PhGetProcessPeb32(_In_ HANDLE ProcessHandle, _Out_ PVOID *Peb32);

/**
 * References the specified object.
 *
 * \param Object A pointer to the object to reference.
 *
 * \return The object.
 */
PVOID PhReferenceObject(_In_ PVOID Object);

/**
 * Calls the delete procedure for an object and frees its allocated storage.
 *
 * \param ObjectHeader A pointer to the object header of an allocated object.
 */
VOID PhpFreeObject(_In_ PPH_OBJECT_HEADER ObjectHeader);

/**
 * Allocates a object.
 *
 * \param ObjectSize The size of the object.
 * \param ObjectType The type of the object.
 *
 * \return A pointer to the newly allocated object.
 */
PVOID PhCreateObject(_In_ SIZE_T ObjectSize, _In_ PPH_OBJECT_TYPE ObjectType);

/**
 * Frees a block of memory to a free list.
 *
 * \param FreeList A pointer to a free list object.
 * \param Memory A pointer to a block of memory.
 */
VOID PhFreeToFreeList(_Inout_ PPH_FREE_LIST FreeList, _In_ PVOID Memory);

/**
 * Allocates storage for an object.
 *
 * \param ObjectType The type of the object.
 * \param ObjectSize The size of the object, excluding the header.
 */
PPH_OBJECT_HEADER PhpAllocateObject(_In_ PPH_OBJECT_TYPE ObjectType, _In_ SIZE_T ObjectSize);

/**
 * Allocates a block of memory from a free list.
 *
 * \param FreeList A pointer to a free list object.
 *
 * \return A pointer to the allocated block of memory. The memory must be freed using
 * PhFreeToFreeList(). The block is guaranteed to be aligned at MEMORY_ALLOCATION_ALIGNMENT bytes.
 */
PVOID PhAllocateFromFreeList(_Inout_ PPH_FREE_LIST FreeList);

/**
 * Allocates a block of memory.
 *
 * \param Size The number of bytes to allocate.
 *
 * \return A pointer to the allocated block of memory.
 *
 * \remarks If the function fails to allocate the block of memory, it raises an exception. The block
 * is guaranteed to be aligned at MEMORY_ALLOCATION_ALIGNMENT bytes.
 */
_Check_return_ _Ret_notnull_ _Post_writable_byte_size_(Size) PVOID PhAllocate(_In_ SIZE_T Size);

NTSYSAPI
PVOID
NTAPI
RtlAllocateHeap(_In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _In_ SIZE_T Size);
