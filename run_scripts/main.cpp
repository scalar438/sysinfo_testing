#include <Windows.h>
#include <iostream>
#include <string_view>

bool run_cross(std::string_view p1, std::string_view p2)
{
	return true;
}

int main(int argc, char *argv[])
{
	for (int i = 1; i <= argc; ++i)
	{
		for (int j = i; j <= argc; ++j)
		{
			if (!run_cross(argv[i], argv[j]))
			{
				std::cerr << "Something went wrong\n";
				return -1;
			}
		}
	}
}