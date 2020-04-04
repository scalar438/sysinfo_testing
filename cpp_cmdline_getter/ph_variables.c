#include "ph_variables.h"
#include "ph_defines.h"
#include "ph_types.h"

#include "sys_func.h"

ULONG WindowsVersion = WINDOWS_NEW;

PVOID PhHeapHandle = NULL;

PPH_STRING PhSharedEmptyString = NULL;

PPH_OBJECT_TYPE PhStringType = NULL;

RTL_OSVERSIONINFOEXW PhOsVersion = {0};

VOID PhInitializeWindowsVersion(VOID)
{
	RTL_OSVERSIONINFOEXW versionInfo;
	ULONG majorVersion;
	ULONG minorVersion;
	ULONG buildVersion;

	memset(&versionInfo, 0, sizeof(RTL_OSVERSIONINFOEXW));
	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

	if (!NT_SUCCESS(RtlGetVersion(&versionInfo)))
	{
		WindowsVersion = WINDOWS_NEW;
		return;
	}

	memcpy(&PhOsVersion, &versionInfo, sizeof(RTL_OSVERSIONINFOEXW));
	majorVersion = versionInfo.dwMajorVersion;
	minorVersion = versionInfo.dwMinorVersion;
	buildVersion = versionInfo.dwBuildNumber;

	// Windows 7, Windows Server 2008 R2
	if (majorVersion == 6 && minorVersion == 1)
	{
		WindowsVersion = WINDOWS_7;
	}
	// Windows 8, Windows Server 2012
	else if (majorVersion == 6 && minorVersion == 2)
	{
		WindowsVersion = WINDOWS_8;
	}
	// Windows 8.1, Windows Server 2012 R2
	else if (majorVersion == 6 && minorVersion == 3)
	{
		WindowsVersion = WINDOWS_8_1;
	}
	// Windows 10, Windows Server 2016
	else if (majorVersion == 10 && minorVersion == 0)
	{
		if (buildVersion >= 18363)
		{
			WindowsVersion = WINDOWS_10_19H2;
		}
		else if (buildVersion >= 18362)
		{
			WindowsVersion = WINDOWS_10_19H1;
		}
		else if (buildVersion >= 17763)
		{
			WindowsVersion = WINDOWS_10_RS5;
		}
		else if (buildVersion >= 17134)
		{
			WindowsVersion = WINDOWS_10_RS4;
		}
		else if (buildVersion >= 16299)
		{
			WindowsVersion = WINDOWS_10_RS3;
		}
		else if (buildVersion >= 15063)
		{
			WindowsVersion = WINDOWS_10_RS2;
		}
		else if (buildVersion >= 14393)
		{
			WindowsVersion = WINDOWS_10_RS1;
		}
		else if (buildVersion >= 10586)
		{
			WindowsVersion = WINDOWS_10_TH2;
		}
		else if (buildVersion >= 10240)
		{
			WindowsVersion = WINDOWS_10;
		}
		else
		{
			WindowsVersion = WINDOWS_10;
		}
	}
	else
	{
		WindowsVersion = WINDOWS_NEW;
	}
}

void initHeapHandle()
{
    PhHeapHandle = RtlCreateHeap(HEAP_GROWABLE | HEAP_CLASS_1, NULL,
                                 2 * 1024 * 1024, // 2 MB
                                 1024 * 1024,     // 1 MB
                                 NULL, NULL);
}

void ph_init()
{
    PhInitializeWindowsVersion();
    initHeapHandle();
}

