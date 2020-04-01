#include <Windows.h>
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
