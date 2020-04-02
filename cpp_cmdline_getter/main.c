#include "ph_funcs.h"
#include <Windows.h>
#include <stdio.h>
#include <winnt.h>

int main()
{
	printf("%d\n", GetCurrentProcessId());
	DWORD pid;
	scanf("%d", &pid);
	HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (handle == NULL)
	{
		printf("Cannot open process handle\n");
		return 0;
	}
	PPH_STRING cmdline;
	PhGetProcessCommandLine(handle, &cmdline);
}