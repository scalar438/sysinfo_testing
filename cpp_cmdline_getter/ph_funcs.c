#include <Windows.h>
#include <ntstatus.h>
#include <winnt.h>

#include "ph_defines.h"
#include "ph_funcs.h"
#include "ph_variables.h"

NTSTATUS PhGetProcessCommandLine(_In_ HANDLE ProcessHandle, _Out_ PPH_STRING *CommandLine)
{
	if (WindowsVersion >= WINDOWS_8_1)
	{
		NTSTATUS status;
		PUNICODE_STRING commandLine;

		status =
		    PhpQueryProcessVariableSize(ProcessHandle, ProcessCommandLineInformation, &commandLine);

		if (NT_SUCCESS(status))
		{
			*CommandLine = PhCreateStringFromUnicodeString(commandLine);
			PhFree(commandLine);

			return status;
		}
	}

	return PhGetProcessPebString(ProcessHandle, PhpoCommandLine, CommandLine);
}

/**
 * Frees a block of memory allocated with PhAllocate().
 *
 * \param Memory A pointer to a block of memory.
 */
VOID PhFree(_Frees_ptr_opt_ PVOID Memory)
{
	RtlFreeHeap(PhHeapHandle, 0, Memory);
}

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
                               _Out_ PPH_STRING *String)
{
	NTSTATUS status;
	PPH_STRING string;
	ULONG offset;

#define PEB_OFFSET_CASE(Enum, Field)                                             \
	case Enum: offset = FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, Field); break; \
	case Enum | PhpoWow64: offset = FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS32, Field); break

	switch (Offset)
	{
		PEB_OFFSET_CASE(PhpoCurrentDirectory, CurrentDirectory);
		PEB_OFFSET_CASE(PhpoDllPath, DllPath);
		PEB_OFFSET_CASE(PhpoImagePathName, ImagePathName);
		PEB_OFFSET_CASE(PhpoCommandLine, CommandLine);
		PEB_OFFSET_CASE(PhpoWindowTitle, WindowTitle);
		PEB_OFFSET_CASE(PhpoDesktopInfo, DesktopInfo);
		PEB_OFFSET_CASE(PhpoShellInfo, ShellInfo);
		PEB_OFFSET_CASE(PhpoRuntimeData, RuntimeData);
	default: return STATUS_INVALID_PARAMETER_2;
	}

	if (!(Offset & PhpoWow64))
	{
		PROCESS_BASIC_INFORMATION basicInfo;
		PVOID processParameters;
		UNICODE_STRING unicodeString;

		// Get the PEB address.
		if (!NT_SUCCESS(status = PhGetProcessBasicInformation(ProcessHandle, &basicInfo)))
			return status;

		// Read the address of the process parameters.
		if (!NT_SUCCESS(
		        status = NtReadVirtualMemory(
		            ProcessHandle,
		            PTR_ADD_OFFSET(basicInfo.PebBaseAddress, FIELD_OFFSET(PEB, ProcessParameters)),
		            &processParameters, sizeof(PVOID), NULL)))
			return status;

		// Read the string structure.
		if (!NT_SUCCESS(status = NtReadVirtualMemory(ProcessHandle,
		                                             PTR_ADD_OFFSET(processParameters, offset),
		                                             &unicodeString, sizeof(UNICODE_STRING), NULL)))
			return status;

		if (unicodeString.Length == 0)
		{
			*String = PhReferenceEmptyString();
			return status;
		}

		string = PhCreateStringEx(NULL, unicodeString.Length);

		// Read the string contents.
		if (!NT_SUCCESS(status = NtReadVirtualMemory(ProcessHandle, unicodeString.Buffer,
		                                             string->Buffer, string->Length, NULL)))
		{
			PhDereferenceObject(string);
			return status;
		}
	}
	else
	{
		PVOID peb32;
		ULONG processParameters32;
		UNICODE_STRING32 unicodeString32;

		if (!NT_SUCCESS(status = PhGetProcessPeb32(ProcessHandle, &peb32))) return status;

		if (!NT_SUCCESS(status = NtReadVirtualMemory(
		                    ProcessHandle,
		                    PTR_ADD_OFFSET(peb32, FIELD_OFFSET(PEB32, ProcessParameters)),
		                    &processParameters32, sizeof(ULONG), NULL)))
			return status;

		if (!NT_SUCCESS(status = NtReadVirtualMemory(
		                    ProcessHandle, PTR_ADD_OFFSET(processParameters32, offset),
		                    &unicodeString32, sizeof(UNICODE_STRING32), NULL)))
			return status;

		if (unicodeString32.Length == 0)
		{
			*String = PhReferenceEmptyString();
			return status;
		}

		string = PhCreateStringEx(NULL, unicodeString32.Length);

		// Read the string contents.
		if (!NT_SUCCESS(status =
		                    NtReadVirtualMemory(ProcessHandle, UlongToPtr(unicodeString32.Buffer),
		                                        string->Buffer, string->Length, NULL)))
		{
			PhDereferenceObject(string);
			return status;
		}
	}

	*String = string;

	return status;
}

/**
 * Obtains a reference to a zero-length string.
 */
PPH_STRING PhReferenceEmptyString(VOID)
{
	PPH_STRING string;
	PPH_STRING newString;

	string = InterlockedCompareExchangePointer(&PhSharedEmptyString, NULL, NULL);

	if (!string)
	{
		newString = PhCreateStringEx(NULL, 0);

		string = InterlockedCompareExchangePointer(&PhSharedEmptyString, newString, NULL);

		if (!string)
		{
			string = newString; // success
		}
		else
		{
			PhDereferenceObject(newString);
		}
	}

	return PhReferenceObject(string);
}

/**
 * Dereferences the specified object.
 * The object will be freed if its reference count reaches 0.
 *
 * \param Object A pointer to the object to dereference.
 */
VOID PhDereferenceObject(_In_ PVOID Object)
{
	PPH_OBJECT_HEADER objectHeader;
	LONG newRefCount;

	objectHeader = PhObjectToObjectHeader(Object);
	// Decrement the reference count.
	newRefCount = _InterlockedDecrement(&objectHeader->RefCount);
	ASSUME_ASSERT(newRefCount >= 0);
	ASSUME_ASSERT(!(newRefCount < 0));

	// Free the object if it has 0 references.
	if (newRefCount == 0)
	{
		PhpFreeObject(objectHeader);
	}
}

/**
 * Gets a process' WOW64 PEB address.
 *
 * \param ProcessHandle A handle to a process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION access.
 * \param Peb32 A variable which receives the base address of the process' WOW64 PEB. If the process
 * is 64-bit, the variable receives NULL.
 */
NTSTATUS
PhGetProcessPeb32(_In_ HANDLE ProcessHandle, _Out_ PVOID *Peb32)
{
	NTSTATUS status;
	ULONG_PTR wow64;

	status = NtQueryInformationProcess(ProcessHandle, ProcessWow64Information, &wow64,
	                                   sizeof(ULONG_PTR), NULL);

	if (NT_SUCCESS(status))
	{
		*Peb32 = (PVOID)wow64;
	}

	return status;
}

/**
 * References the specified object.
 *
 * \param Object A pointer to the object to reference.
 *
 * \return The object.
 */
PVOID PhReferenceObject(_In_ PVOID Object)
{
	PPH_OBJECT_HEADER objectHeader;

	objectHeader = PhObjectToObjectHeader(Object);
	// Increment the reference count.
	_InterlockedIncrement(&objectHeader->RefCount);

	return Object;
}

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
                                     _Out_ PVOID *Buffer)
{
	NTSTATUS status;
	PVOID buffer;
	ULONG returnLength = 0;

	status =
	    NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, NULL, 0, &returnLength);

	if (status != STATUS_BUFFER_OVERFLOW && status != STATUS_BUFFER_TOO_SMALL &&
	    status != STATUS_INFO_LENGTH_MISMATCH)
		return status;

	buffer = PhAllocate(returnLength);
	status = NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, buffer, returnLength,
	                                   &returnLength);

	if (NT_SUCCESS(status))
	{
		*Buffer = buffer;
	}
	else
	{
		PhFree(buffer);
	}

	return status;
}

PPH_STRING
PhCreateStringFromUnicodeString(_In_ PUNICODE_STRING UnicodeString)
{
	if (UnicodeString->Length == 0) return PhReferenceEmptyString();

	return PhCreateStringEx(UnicodeString->Buffer, UnicodeString->Length);
}

/**
 * Gets basic information for a process.
 *
 * \param ProcessHandle A handle to a process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION access.
 * \param BasicInformation A variable which receives the information.
 */
NTSTATUS
PhGetProcessBasicInformation(_In_ HANDLE ProcessHandle,
                             _Out_ PPROCESS_BASIC_INFORMATION BasicInformation)
{
	return NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, BasicInformation,
	                                 sizeof(PROCESS_BASIC_INFORMATION), NULL);
}

/**
 * Creates a string object using a specified length.
 *
 * \param Buffer A null-terminated Unicode string.
 * \param Length The length, in bytes, of the string.
 */
PPH_STRING PhCreateStringEx(_In_opt_ PWCHAR Buffer, _In_ SIZE_T Length)
{
	PPH_STRING string;

	string = PhCreateObject(UFIELD_OFFSET(PH_STRING, Data) + Length +
	                            sizeof(UNICODE_NULL), // Null terminator for compatibility
	                        PhStringType);

	// assert(!(Length & 1));
	string->Length                                  = Length;
	string->Buffer                                  = string->Data;
	*(PWCHAR)PTR_ADD_OFFSET(string->Buffer, Length) = UNICODE_NULL;

	if (Buffer)
	{
		memcpy(string->Buffer, Buffer, Length);
	}

	return string;
}

/**
 * Allocates a object.
 *
 * \param ObjectSize The size of the object.
 * \param ObjectType The type of the object.
 *
 * \return A pointer to the newly allocated object.
 */
PVOID PhCreateObject(_In_ SIZE_T ObjectSize, _In_ PPH_OBJECT_TYPE ObjectType)
{
	NTSTATUS status = STATUS_SUCCESS;
	PPH_OBJECT_HEADER objectHeader;

	// Allocate storage for the object. Note that this includes the object header followed by the
	// object body.
	objectHeader = PhpAllocateObject(ObjectType, ObjectSize);

	// Object type statistics.
	_InterlockedIncrement((PLONG)&ObjectType->NumberOfObjects);

	// Initialize the object header.
	objectHeader->RefCount  = 1;
	objectHeader->TypeIndex = ObjectType->TypeIndex;
	// objectHeader->Flags is set by PhpAllocateObject.

	return PhObjectHeaderToObject(objectHeader);
}

PH_FREE_LIST PhObjectSmallFreeList;
PPH_OBJECT_TYPE PhObjectTypeTable[PH_OBJECT_TYPE_TABLE_SIZE];

/**
 * Calls the delete procedure for an object and frees its allocated storage.
 *
 * \param ObjectHeader A pointer to the object header of an allocated object.
 */
VOID PhpFreeObject(_In_ PPH_OBJECT_HEADER ObjectHeader)
{
	PPH_OBJECT_TYPE objectType;

	objectType = PhObjectTypeTable[ObjectHeader->TypeIndex];

	// Object type statistics.
	_InterlockedDecrement(&objectType->NumberOfObjects);

	// Call the delete procedure if we have one.
	if (objectType->DeleteProcedure)
	{
		objectType->DeleteProcedure(PhObjectHeaderToObject(ObjectHeader), 0);
	}

	if (ObjectHeader->Flags & PH_OBJECT_FROM_TYPE_FREE_LIST)
	{
		PhFreeToFreeList(&objectType->FreeList, ObjectHeader);
	}
	else if (ObjectHeader->Flags & PH_OBJECT_FROM_SMALL_FREE_LIST)
	{
		PhFreeToFreeList(&PhObjectSmallFreeList, ObjectHeader);
	}
	else
	{
		PhFree(ObjectHeader);
	}
}

/**
 * Frees a block of memory to a free list.
 *
 * \param FreeList A pointer to a free list object.
 * \param Memory A pointer to a block of memory.
 */
VOID PhFreeToFreeList(_Inout_ PPH_FREE_LIST FreeList, _In_ PVOID Memory)
{
	PPH_FREE_LIST_ENTRY entry;

	entry = CONTAINING_RECORD(Memory, PH_FREE_LIST_ENTRY, Body);

	// We don't enforce Count <= MaximumCount (that would require locking),
	// but we do check it.
	if (FreeList->Count < FreeList->MaximumCount)
	{
		RtlInterlockedPushEntrySList(&FreeList->ListHead, &entry->ListEntry);
		_InterlockedIncrement((PLONG)&FreeList->Count);
	}
	else
	{
		PhFree(entry);
	}
}

/**
 * Allocates storage for an object.
 *
 * \param ObjectType The type of the object.
 * \param ObjectSize The size of the object, excluding the header.
 */
PPH_OBJECT_HEADER PhpAllocateObject(_In_ PPH_OBJECT_TYPE ObjectType, _In_ SIZE_T ObjectSize)
{
	PPH_OBJECT_HEADER objectHeader;

	if (ObjectType->Flags & PH_OBJECT_TYPE_USE_FREE_LIST)
	{
		// assert(ObjectType->FreeList.Size == PhAddObjectHeaderSize(ObjectSize));

		objectHeader        = PhAllocateFromFreeList(&ObjectType->FreeList);
		objectHeader->Flags = PH_OBJECT_FROM_TYPE_FREE_LIST;
	}
	else if (ObjectSize <= PH_OBJECT_SMALL_OBJECT_SIZE)
	{
		objectHeader        = PhAllocateFromFreeList(&PhObjectSmallFreeList);
		objectHeader->Flags = PH_OBJECT_FROM_SMALL_FREE_LIST;
	}
	else
	{
		objectHeader        = PhAllocate(PhAddObjectHeaderSize(ObjectSize));
		objectHeader->Flags = 0;
	}

	return objectHeader;
}

/**
 * Allocates a block of memory from a free list.
 *
 * \param FreeList A pointer to a free list object.
 *
 * \return A pointer to the allocated block of memory. The memory must be freed using
 * PhFreeToFreeList(). The block is guaranteed to be aligned at MEMORY_ALLOCATION_ALIGNMENT bytes.
 */
PVOID PhAllocateFromFreeList(_Inout_ PPH_FREE_LIST FreeList)
{
	PPH_FREE_LIST_ENTRY entry;
	PSLIST_ENTRY listEntry;

	listEntry = RtlInterlockedPopEntrySList(&FreeList->ListHead);

	if (listEntry)
	{
		_InterlockedDecrement((PLONG)&FreeList->Count);
		entry = CONTAINING_RECORD(listEntry, PH_FREE_LIST_ENTRY, ListEntry);
	}
	else
	{
		entry = PhAllocate(UFIELD_OFFSET(PH_FREE_LIST_ENTRY, Body) + FreeList->Size);
	}

	return &entry->Body;
}

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
_Check_return_ _Ret_notnull_ _Post_writable_byte_size_(Size) PVOID PhAllocate(_In_ SIZE_T Size)
{
	return RtlAllocateHeap(PhHeapHandle, HEAP_GENERATE_EXCEPTIONS, Size);
}
