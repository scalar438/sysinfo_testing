extern crate ntapi;
extern crate winapi;

use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::HANDLE;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use ntapi::ntpsapi::{NtQueryInformationProcess, PROCESS_BASIC_INFORMATION};

use std::mem::size_of;
use std::ptr::null_mut;

struct HandleWrapper {
	handle: HANDLE,
}

impl Drop for HandleWrapper {
	fn drop(&mut self) {
		unsafe {
			CloseHandle(self.handle);
		}
	}
}

fn get_process_handler(pid: DWORD) -> Option<HandleWrapper> {
	if pid == 0 {
		return None;
	}
	let options = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
	let process_handler = unsafe { OpenProcess(options, FALSE, pid) };
	if process_handler.is_null() {
		None
	} else {
		Some(HandleWrapper {
			handle: process_handler,
		})
	}
}

fn parse_command_line(s: &str) -> Vec<String> {
	let mut res = Vec::new();
	let mut cur = String::new();
	let mut prev_backslash = false;
	let mut quoted_arg = false;
	for c in s.chars() {
		match c {
			'\\' => {
				if prev_backslash {
					// Push previous bacslash, not current
					cur.push('\\');
				}
				prev_backslash = true;
			}
			'"' => {
				if prev_backslash {
					cur.push('"');
					prev_backslash = false;
				} else {
					if quoted_arg {
						res.push(cur.clone());
						cur.truncate(0);
						quoted_arg = false;
					} else {
						quoted_arg = true;
					}
				}
			}
			' ' => {
				if prev_backslash {
					cur.push('\\');
					prev_backslash = false;
				}
				if quoted_arg {
					cur.push(' ');
				} else if !cur.is_empty() {
					res.push(cur.clone());
					cur.truncate(0);
				}
			}
			_ => {
				if prev_backslash {
					cur.push('\\');
					prev_backslash = false;
				}
				cur.push(c);
			}
		}
	}
	if prev_backslash {
		cur.push('\\');
	}
	if !cur.is_empty() {
		res.push(cur);
	}

	res
}

pub fn get_cmd_line(pid: DWORD) -> Vec<String> {
	use ntapi::ntpebteb::{PEB, PPEB};
	use ntapi::ntrtl::{PRTL_USER_PROCESS_PARAMETERS, RTL_USER_PROCESS_PARAMETERS};
	use winapi::shared::basetsd::SIZE_T;
	use winapi::um::memoryapi::ReadProcessMemory;

	unsafe {
		let handle = match get_process_handler(pid) {
			Some(h) => h,
			None => return Vec::new(),
		};

		let handle = handle.handle;

		let mut pinfo = std::mem::MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
		if NtQueryInformationProcess(
			handle,
			0, // ProcessBasicInformation
			pinfo.as_mut_ptr() as *mut _,
			size_of::<PROCESS_BASIC_INFORMATION>() as u32,
			null_mut(),
		) != 0
		{
			return Vec::new();
		}
		let pinfo = pinfo.assume_init();

		let ppeb: PPEB = pinfo.PebBaseAddress;
		let mut peb_copy = std::mem::MaybeUninit::<PEB>::uninit();
		if ReadProcessMemory(
			handle,
			ppeb as *mut _,
			peb_copy.as_mut_ptr() as *mut _,
			size_of::<PEB>() as SIZE_T,
			null_mut(),
		) != TRUE
		{
			return Vec::new();
		}
		let peb_copy = peb_copy.assume_init();

		let proc_param = peb_copy.ProcessParameters;
		let mut rtl_proc_param_copy =
			std::mem::MaybeUninit::<RTL_USER_PROCESS_PARAMETERS>::uninit();
		if ReadProcessMemory(
			handle,
			proc_param as *mut PRTL_USER_PROCESS_PARAMETERS as *mut _,
			rtl_proc_param_copy.as_mut_ptr() as *mut _,
			size_of::<RTL_USER_PROCESS_PARAMETERS>() as SIZE_T,
			null_mut(),
		) != TRUE
		{
			return Vec::new();
		}
		let rtl_proc_param_copy = rtl_proc_param_copy.assume_init();

		let len = rtl_proc_param_copy.CommandLine.Length as usize;
		if len % 2 == 1 {
			// Just in case, I don't know can it happen or not
			return Vec::new();
		}
		let len = len / 2;
		let mut buffer_copy: Vec<u16> = Vec::with_capacity(len);
		buffer_copy.set_len(len);
		if ReadProcessMemory(
			handle,
			rtl_proc_param_copy.CommandLine.Buffer as *mut _,
			buffer_copy.as_mut_ptr() as *mut _,
			len * 2 as SIZE_T,
			null_mut(),
		) != TRUE
		{
			return Vec::new();
		}

		let cmdline_full = String::from_utf16_lossy(&buffer_copy);
		println!("Cmdline: {}", cmdline_full);
		parse_command_line(&cmdline_full)
	}
}

#[cfg(test)]
mod test {

	use super::*;

	#[test]
	fn test_parse_cmdilne() {
		assert_eq!(parse_command_line("a b"), vec!["a", "b"],);
		assert_eq!(parse_command_line(r#"\"a\"     b"#), vec![r#""a""#, "b"]);

		// With spaces
		assert_eq!(parse_command_line(r#""a  b"  c"#), vec!["a  b", "c"]);

		// With quotes
		assert_eq!(parse_command_line(r#"a\"b  c"#), vec![r#"a"b"#, "c"]);

		// With quotes, spaces and backslashes
		assert_eq!(
			parse_command_line(r#" "a \ \"b" \\  "\\ c\""#),
			vec![r#"a \ "b"#, "\\\\", r#"\\ c""#]
		);
		assert_eq!(
			parse_command_line(
				r#"arg1 arg2\\with_backslash_without_space "arg3 with \"spaces \ and backslash" "#
			),
			vec![
				"arg1",
				r#"arg2\\with_backslash_without_space"#,
				r#"arg3 with "spaces \ and backslash"#
			]
		);
		assert_eq!(parse_command_line(r#"qwe q\"#), vec!["qwe", "q\\"]);
		assert_eq!(parse_command_line(r#"qwe \\"\"#), vec!["qwe", "\\\"\\"]);
		assert_eq!(
			parse_command_line(r#""print_args" \" ' "\\\" \\\"""#),
			vec!["print_args", "\"", "\'", "\\\" \\\""]
		);
	}
	fn check(args: &[&str]) {
		let mut command = std::process::Command::new("print_args");
		let mut expected = vec!["print_args"]; // First arg is always in quotes

		let mut c = &mut command;
		for s in args {
			c = c.arg(s);
			expected.push(s.to_owned());
		}

		let mut command = command.spawn().unwrap();
		let cmdline = get_cmd_line(command.id());

		// println!("{}", command);

		assert_eq!(cmdline, expected);
		command.wait().unwrap();
	}

	#[test]
	fn test1() {
		//	check(&["qwerty"]);
		//	check(&["first arg with spaces", "second_arg"]);
		//	check(&["first_arg_without_spaces", "second arg with spaces"]);
		//	check(&["arg_with_\"quotes\""]);
		//check(&["arg_with_\"quotes\" \\   and spaces"]);
		//check(&["arg_with_\"backslash"]);
		check(&["\"", "'", r#"\" \""#]);
	}
}
