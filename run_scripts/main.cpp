#include <Windows.h>
#include <iostream>
#include <string_view>

#include "handle.hpp"

// 0 - no error
// 1 - program didn't return command line
// 2 - something went wrong
int run_cross(std::string_view p1, std::string_view p2)
{
	std::string cmdline1 = std::string(p1) + " " + " first_arg";
	std::string cmdline2 = std::string(p2) + " " + " second_arg";
	SECURITY_ATTRIBUTES sa;
	sa.bInheritHandle = true;
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = NULL;

	//CreateProcessA(NULL, &cmdline1[0], &sa, &sa, true, )
	return 0;
}

int main(int argc, char *argv[])
{
	for (int i = 1; i <= argc; ++i)
	{
		for (int j = i; j <= argc; ++j)
		{
			switch (run_cross(argv[i], argv[j]))
			{
			case 0:
				// All ok, do nothing
				break;

			case 1:
				std::cerr << "Program didn't return command line\n";
				std::cerr << "Pair of programs: " << argv[i] << " and " << argv[j] << '\n';
				return 1;

			case 2: std::cerr << "Something went wrong\n"; return -1;
			}
		}
	}
}