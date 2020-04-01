#pragma once

#include "ph_defines.h"

#include <Windows.h>
#include <winnt.h>

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

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/** Specifies a PEB string. */
typedef enum _PH_PEB_OFFSET
{
	PhpoCurrentDirectory,
	PhpoDllPath,
	PhpoImagePathName,
	PhpoCommandLine,
	PhpoWindowTitle,
	PhpoDesktopInfo,
	PhpoShellInfo,
	PhpoRuntimeData,
	PhpoTypeMask = 0xffff,

	PhpoWow64 = 0x10000
} PH_PEB_OFFSET;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation,     // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits,          // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters,           // q: IO_COUNTERS
	ProcessVmCounters,           // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes,                // q: KERNEL_USER_TIMES
	ProcessBasePriority,         // s: KPRIORITY
	ProcessRaisePriority,        // s: ULONG
	ProcessDebugPort,            // q: HANDLE
	ProcessExceptionPort,        // s: PROCESS_EXCEPTION_PORT
	ProcessAccessToken,          // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation,       // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize,              // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers,       // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch,      // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass,             // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount,   // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask,  // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap,     // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation,    // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information,      // q: ULONG_PTR
	ProcessImageFileName,         // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination,    // qs: ULONG
	ProcessDebugObjectHandle,     // q: HANDLE // 30
	ProcessDebugFlags,            // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority,    // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags,  // qs: ULONG
	ProcessResourceManagement,      // ProcessTlsInformation // PROCESS_TLS_INFORMATION
	ProcessCookie,                  // q: ULONG
	ProcessImageInformation,        // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime,               // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority,            // q: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback, // qs: PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation,   // s: PROCESS_STACK_ALLOCATION_INFORMATION,
	// PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx,          // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32,         // q: UNICODE_STRING
	ProcessImageFileMapping,           // q: HANDLE (input)
	ProcessAffinityUpdateMode,         // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode,       // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation,           // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess,         // q: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation,          // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation,          // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy,           // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessKeepAliveCount,     // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles,  // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl,  // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable,        // q: ULONG[] // since WINBLUE
	ProcessCheckStackExtentsMode,
	ProcessCommandLineInformation,   // q: UNICODE_STRING // 60
	ProcessProtectionInformation,    // q: PS_PROTECTION
	ProcessMemoryExhaustion,         // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation,         // PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation,   // PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation,
	ProcessAllowedCpuSetsInformation,
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation,                 // PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate,                            // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation, // PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation,
	ProcessSubsystemInformation,   // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues,           // PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
	ProcessActivityThrottleState,  // PROCESS_ACTIVITY_THROTTLE_STATE
	ProcessActivityThrottlePolicy, // PROCESS_ACTIVITY_THROTTLE_POLICY
	ProcessWin32kSyscallFilterInformation,
	ProcessDisableSystemAllowedCpuSets,    // 80
	ProcessWakeInformation,                // PROCESS_WAKE_INFORMATION
	ProcessEnergyTrackingState,            // PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage,
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging,          // PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation,                 // PROCESS_UPTIME_INFORMATION
	ProcessImageSection,                      // q: HANDLE
	ProcessDebugAuthInformation,              // since REDSTONE4 // 90
	ProcessSystemResourceManagement,          // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber,                    // q: ULONGLONG
	ProcessLoaderDetour,                      // since REDSTONE5
	ProcessSecurityDomainInformation,         // PROCESS_SECURITY_DOMAIN_INFORMATION
	ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
	ProcessEnableLogging,                     // PROCESS_LOGGING_INFORMATION
	ProcessLeapSecondInformation,             // PROCESS_LEAP_SECOND_INFORMATION
	ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since
	// 19H1
	ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
	MaxProcessInfoClass
} PROCESSINFOCLASS;

// private
typedef struct _API_SET_NAMESPACE
{
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

// symbols
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _RTL_USER_PROCESS_PARAMETERS *PRTL_USER_PROCESS_PARAMETERS;

// symbols
typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union {
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};

	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID IFEOKey;
	PSLIST_HEADER AtlThunkSListPtr;
	union {
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1; // REDSTONE5
			ULONG ReservedBits0 : 24;
		};
	};
	union {
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PAPI_SET_NAMESPACE ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];

	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData; // HotpatchInformation
	PVOID *ReadOnlyStaticServerData;

	PVOID AnsiCodePageData;     // PCPTABLEINFO
	PVOID OemCodePageData;      // PCPTABLEINFO
	PVOID UnicodeCaseTableData; // PNLSTABLEINFO

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	ULARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps; // PHEAP

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ActiveProcessAffinityMask;
	GDI_HANDLE_BUFFER GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

	UNICODE_STRING CSDVersion;

	PVOID ActivationContextData;              // ACTIVATION_CONTEXT_DATA
	PVOID ProcessAssemblyStorageMap;          // ASSEMBLY_STORAGE_MAP
	PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID SystemAssemblyStorageMap;           // ASSEMBLY_STORAGE_MAP

	SIZE_T MinimumStackCommit;

	PVOID SparePointers[4]; // 19H1 (previously FlsCallback to FlsHighIndex)
	ULONG SpareUlongs[5];   // 19H1
	// PVOID* FlsCallback;
	// LIST_ENTRY FlsListHead;
	// PVOID FlsBitmap;
	// ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	// ULONG FlsHighIndex;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pUnused; // pContextData
	PVOID pImageHeaderHash;
	union {
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	PRTL_CRITICAL_SECTION TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[128];
	PVOID TelemetryCoverageHeader; // REDSTONE3
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags; // REDSTONE4
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	struct _LEAP_SECOND_DATA *LeapSecondData; // REDSTONE5
	union {
		ULONG LeapSecondFlags;
		struct
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		};
	};
	ULONG NtGlobalFlag2;
} PEB, *PPEB;

typedef struct _STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG Buffer;
} STRING32, *PSTRING32;

typedef STRING32 UNICODE_STRING32, *PUNICODE_STRING32;

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];

// This isn't in NT, but it's useful.
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _QUAD_PTR
{
    ULONG_PTR DoNotUseThisField1;
    ULONG_PTR DoNotUseThisField2;
} QUAD_PTR, *PQUAD_PTR;

/**
 * The object header contains object manager information including the reference count of an object
 * and its type.
 */
typedef struct _PH_OBJECT_HEADER
{
    union
    {
        struct
        {
            USHORT TypeIndex;
            UCHAR Flags;
            UCHAR Reserved1;
#ifdef _WIN64
            ULONG Reserved2;
#endif
            union
            {
                LONG RefCount;
                struct
                {
                    LONG SavedTypeIndex : 16;
                    LONG SavedFlags : 8;
                    LONG Reserved : 7;
                    LONG DeferDelete : 1; // MUST be the high bit, so that RefCount < 0 when deferring delete
                };
            };
#ifdef _WIN64
            ULONG Reserved3;
#endif
        };
        SLIST_ENTRY DeferDeleteListEntry;
    };

#ifdef DEBUG
    PVOID StackBackTrace[16];
    LIST_ENTRY ObjectListEntry;
#endif

    /**
     * The body of the object. For use by the \ref PhObjectToObjectHeader and
     * \ref PhObjectHeaderToObject macros.
     */
    QUAD_PTR Body;
} PH_OBJECT_HEADER, *PPH_OBJECT_HEADER;

typedef struct _PEB32
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union {
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};
	WOW64_POINTER(HANDLE) Mutant;

	WOW64_POINTER(PVOID) ImageBaseAddress;
	WOW64_POINTER(PPEB_LDR_DATA) Ldr;
	WOW64_POINTER(PRTL_USER_PROCESS_PARAMETERS) ProcessParameters;
	WOW64_POINTER(PVOID) SubSystemData;
	WOW64_POINTER(PVOID) ProcessHeap;
	WOW64_POINTER(PRTL_CRITICAL_SECTION) FastPebLock;
	WOW64_POINTER(PVOID) AtlThunkSListPtr;
	WOW64_POINTER(PVOID) IFEOKey;
	union {
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
	};
	union {
		WOW64_POINTER(PVOID) KernelCallbackTable;
		WOW64_POINTER(PVOID) UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	WOW64_POINTER(PVOID) ApiSetMap;
	ULONG TlsExpansionCounter;
	WOW64_POINTER(PVOID) TlsBitmap;
	ULONG TlsBitmapBits[2];
	WOW64_POINTER(PVOID) ReadOnlySharedMemoryBase;
	WOW64_POINTER(PVOID) HotpatchInformation;
	WOW64_POINTER(PVOID *) ReadOnlyStaticServerData;
	WOW64_POINTER(PVOID) AnsiCodePageData;
	WOW64_POINTER(PVOID) OemCodePageData;
	WOW64_POINTER(PVOID) UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	WOW64_POINTER(SIZE_T) HeapSegmentReserve;
	WOW64_POINTER(SIZE_T) HeapSegmentCommit;
	WOW64_POINTER(SIZE_T) HeapDeCommitTotalFreeThreshold;
	WOW64_POINTER(SIZE_T) HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	WOW64_POINTER(PVOID *) ProcessHeaps;

	WOW64_POINTER(PVOID) GdiSharedHandleTable;
	WOW64_POINTER(PVOID) ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	WOW64_POINTER(PRTL_CRITICAL_SECTION) LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	WOW64_POINTER(ULONG_PTR) ActiveProcessAffinityMask;
	GDI_HANDLE_BUFFER32 GdiHandleBuffer;
	WOW64_POINTER(PVOID) PostProcessInitRoutine;

	WOW64_POINTER(PVOID) TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	WOW64_POINTER(PVOID) pShimData;
	WOW64_POINTER(PVOID) AppCompatInfo;

	UNICODE_STRING32 CSDVersion;

	WOW64_POINTER(PVOID) ActivationContextData;
	WOW64_POINTER(PVOID) ProcessAssemblyStorageMap;
	WOW64_POINTER(PVOID) SystemDefaultActivationContextData;
	WOW64_POINTER(PVOID) SystemAssemblyStorageMap;

	WOW64_POINTER(SIZE_T) MinimumStackCommit;

	WOW64_POINTER(PVOID) SparePointers[4];
	ULONG SpareUlongs[5];
	// WOW64_POINTER(PVOID *) FlsCallback;
	// LIST_ENTRY32 FlsListHead;
	// WOW64_POINTER(PVOID) FlsBitmap;
	// ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	// ULONG FlsHighIndex;

	WOW64_POINTER(PVOID) WerRegistrationData;
	WOW64_POINTER(PVOID) WerShipAssertPtr;
	WOW64_POINTER(PVOID) pContextData;
	WOW64_POINTER(PVOID) pImageHeaderHash;
	union {
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	WOW64_POINTER(PVOID) TppWorkerpListLock;
	LIST_ENTRY32 TppWorkerpList;
	WOW64_POINTER(PVOID) WaitOnAddressHashTable[128];
	WOW64_POINTER(PVOID) TelemetryCoverageHeader; // REDSTONE3
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags; // REDSTONE4
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
} PEB32, *PPEB32;

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _CURDIR32
{
	UNICODE_STRING32 DosPath;
	WOW64_POINTER(HANDLE) Handle;
} CURDIR32, *PCURDIR32;

typedef struct _RTL_DRIVE_LETTER_CURDIR32
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING32 DosPath;
} RTL_DRIVE_LETTER_CURDIR32, *PRTL_DRIVE_LETTER_CURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	WOW64_POINTER(HANDLE) ConsoleHandle;
	ULONG ConsoleFlags;
	WOW64_POINTER(HANDLE) StandardInput;
	WOW64_POINTER(HANDLE) StandardOutput;
	WOW64_POINTER(HANDLE) StandardError;

	CURDIR32 CurrentDirectory;
	UNICODE_STRING32 DllPath;
	UNICODE_STRING32 ImagePathName;
	UNICODE_STRING32 CommandLine;
	WOW64_POINTER(PVOID) Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING32 WindowTitle;
	UNICODE_STRING32 DesktopInfo;
	UNICODE_STRING32 ShellInfo;
	UNICODE_STRING32 RuntimeData;
	RTL_DRIVE_LETTER_CURDIR32 CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	WOW64_POINTER(ULONG_PTR) EnvironmentSize;
	WOW64_POINTER(ULONG_PTR) EnvironmentVersion;
	WOW64_POINTER(PVOID) PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

	UNICODE_STRING32 RedirectionDllName; // REDSTONE4
	UNICODE_STRING32 HeapPartitionName;  // 19H1
	WOW64_POINTER(ULONG_PTR) DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;

typedef const STRING *PCSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

	UNICODE_STRING RedirectionDllName; // REDSTONE4
	UNICODE_STRING HeapPartitionName;  // 19H1
	ULONG_PTR DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;