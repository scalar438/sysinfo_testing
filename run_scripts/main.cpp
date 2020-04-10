#include <Windows.h>
#include <iostream>
#include <string>
#include <string_view>
#include <tuple>
#include <optional>
#include <vector>

#include "handle.hpp"

// STARTUPINFO with handle guards
struct SIContainer
{
	STARTUPINFOA si;

	Handle read_stdin;
	Handle write_stdin;

	Handle read_stdout;
	Handle write_stdout;
};

SIContainer get_startup_info(SECURITY_ATTRIBUTES &sa)
{
	SIContainer res;
	memset(&res.si, 0, sizeof(STARTUPINFOA));

	HANDLE h_read, h_write;

	CreatePipe(&h_read, &h_write, &sa, 0);
	Handle read_stdin  = h_read;
	Handle write_stdin = h_write;
	res.si.hStdInput   = h_read;

	CreatePipe(&h_read, &h_write, &sa, 0);
	Handle read_stdout  = h_read;
	Handle write_stdout = h_write;
	res.si.hStdOutput   = h_write;

	return res;
}

// true - no error
bool write_to_handle(const Handle &h, std::string_view v)
{
	DWORD bytes;
	return WriteFile(h.m_handle, v.data(), v.size(), &bytes, NULL) && bytes == v.size();
}

std::optional<std::string> read_to_end(const Handle &h)
{
	std::string res;
	char buffer[128];
	while(true)
	{
		DWORD bytes;
		if(!ReadFile(h.m_handle, buffer, 128, &bytes, NULL))
		{
			return std::optional<std::string>{};
		}
		if(bytes == 0)
		{
			break;
		}
		std::copy(buffer, buffer + bytes, std::back_inserter(res));
	}
	return res;
}

// 0 - no error
// 1 - program didn't return command line
// 2 - something went wrong
int run_cross(std::string_view p1, std::string_view p2)
{
	std::string cmdline1 = std::string(p1) + " " + " first_arg";
	std::string cmdline2 = std::string(p2) + " " + " second_arg";

	SECURITY_ATTRIBUTES sa;
	sa.bInheritHandle       = true;
	sa.nLength              = sizeof(sa);
	sa.lpSecurityDescriptor = NULL;

	Handle out1, out2;

	{
		auto si1 = get_startup_info(sa);
		auto si2 = get_startup_info(sa);

		PROCESS_INFORMATION pi1, pi2;

		if (CreateProcessA(NULL, &cmdline1[0], &sa, &sa, true, 0, NULL, NULL, &si1.si, &pi1) == 0 ||
		    CreateProcessA(NULL, &cmdline2[0], &sa, &sa, true, 0, NULL, NULL, &si1.si, &pi2) == 0)
		{
			return 2;
		}

		if (!write_to_handle(si1.write_stdin, std::to_string(pi1.dwProcessId)) ||
		    !write_to_handle(si2.write_stdin, std::to_string(pi2.dwProcessId)))
		{
			return 2;
		}

		out1 = std::move(si1.read_stdout);
		out2 = std::move(si2.read_stdout);
		// Do not close process && thread handles because there are not too many of them
	}

	auto str1 = read_to_end(out1);
	auto str2 = read_to_end(out2);

	if(!(str1 && str2)) return 2;

	// Do something
	std::cout << *str1 << "\n" << *str2;

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