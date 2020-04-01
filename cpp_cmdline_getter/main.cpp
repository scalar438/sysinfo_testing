#include <Windows.h>
#include <winnt.h>

#include "ph_funcs.h"
#include <iostream>

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