#include "ph_funcs.h"
#include "ph_variables.h"

#include <stdio.h>
#include <winnt.h>

int main()
{
	ph_init();

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