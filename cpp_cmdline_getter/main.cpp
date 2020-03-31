#include <Windows.h>
#include <winnt.h>

#include <iostream>

typedef struct _PH_STRINGREF
{
	/** The length, in bytes, of the string. */
	SIZE_T Length;
	/** The buffer containing the contents of the string. */
	PWCH Buffer;
} PH_STRINGREF, *PPH_STRINGREF;

/**
 * A 16-bit string object, which supports UTF-16.
 *
 * \remarks The \a Length never includes the null terminator. Every string must have a null
 * terminator at the end, for compatibility reasons. The invariant is:
 * \code Buffer[Length / sizeof(WCHAR)] = 0 \endcode
 */
typedef struct _PH_STRING
{
	// Header
	union {
		PH_STRINGREF sr;
		struct
		{
			/** The length, in bytes, of the string. */
			SIZE_T Length;
			/** The buffer containing the contents of the string. */
			PWCH Buffer;
		};
	};

	// Data
	union {
		WCHAR Data[1];
		struct
		{
			/** Reserved. */
			ULONG AllocationFlags;
			/** Reserved. */
			PVOID Allocation;
		};
	};
} PH_STRING, *PPH_STRING;

/**
 * Gets a process' command line.
 *
 * \param ProcessHandle A handle to a process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION. Before Windows 8.1, the handle must also have PROCESS_VM_READ
 * access.
 * \param String A variable which receives a pointer to a string containing the command line. You
 * must free the string using PhDereferenceObject() when you no longer need it.
 */
NTSTATUS PhGetProcessCommandLine(_In_ HANDLE ProcessHandle, _Out_ PPH_STRING *CommandLine);

int main()
{
	std::cout << GetCurrentProcessId() << std::endl;
	DWORD pid;
	std::cin >> pid;
	auto handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (handle == NULL)
	{
		std::cout << "Cannot open process handle\n";
		return 0;
	}
	PPH_STRING cmdline;
	PhGetProcessCommandLine(handle, &cmdline);
}