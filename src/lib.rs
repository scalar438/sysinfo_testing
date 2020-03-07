extern crate libc;
extern crate ntapi;
extern crate winapi;

use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winbase::LocalFree;
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

pub fn get_cmd_line(pid: DWORD) -> Vec<String> {
	use ntapi::ntpebteb::{PEB, PPEB};
	use ntapi::ntrtl::{PRTL_USER_PROCESS_PARAMETERS, RTL_USER_PROCESS_PARAMETERS};
	use std::mem::MaybeUninit;
	use winapi::shared::basetsd::SIZE_T;
	use winapi::um::memoryapi::ReadProcessMemory;
	use winapi::um::shellapi::CommandLineToArgvW;

	unsafe {
		let handle = match get_process_handler(pid) {
			Some(h) => h,
			None => return Vec::new(),
		};

		let handle = handle.handle;

		let mut pinfo = MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
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
		let mut peb_copy = MaybeUninit::<PEB>::uninit();
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
		let mut rtl_proc_param_copy = MaybeUninit::<RTL_USER_PROCESS_PARAMETERS>::uninit();
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
		// For len symbols + '/0'
		let mut buffer_copy: Vec<u8> = Vec::with_capacity(len + 2);
		buffer_copy.set_len(len);
		if ReadProcessMemory(
			handle,
			rtl_proc_param_copy.CommandLine.Buffer as *mut _,
			buffer_copy.as_mut_ptr() as *mut _,
			len as SIZE_T,
			null_mut(),
		) != TRUE
		{
			return Vec::new();
		}
		buffer_copy.push(0);
		buffer_copy.push(0);

		let mut argc = MaybeUninit::<i32>::uninit();
		let argv_p = CommandLineToArgvW(buffer_copy.as_ptr() as *const _, argc.as_mut_ptr());
		if argv_p.is_null() {
			return Vec::new();
		}
		let argc = argc.assume_init();

		let argv = std::slice::from_raw_parts(argv_p, argc as usize);
		let mut res = Vec::new();
		for arg in argv {
			let len = libc::wcslen(*arg);
			let str_slice = std::slice::from_raw_parts(*arg, len);
			res.push(String::from_utf16_lossy(str_slice));
		}

		LocalFree(argv_p as *mut _);

		res
	}
}

#[cfg(test)]
mod test {

	use super::*;

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

		assert_eq!(cmdline, expected);
		command.wait().unwrap();
	}

	#[test]
	fn test1() {
		check(&["qwerty"]);
	}

	#[test]
	fn test2() {
		check(&["first arg with spaces", "second_arg"]);
	}

	#[test]
	fn test3() {
		check(&["first_arg_without_spaces", "second arg with spaces"]);
	}

	#[test]
	fn test4() {
		check(&["arg_with_\"quotes\""]);
	}

	#[test]
	fn test5() {
		check(&["arg_with_\"quotes\" \\   and spaces"]);
	}

	#[test]
	fn test6() {
		check(&["arg_with_\"backslash"]);
	}

	#[test]
	fn test7() {
		check(&["\"", "'", r#"\" \""#]);
	}

	#[test]
	fn test8() {
		check(&["\"", "'", r#"\\\" \""#]);
	}

	#[test]
	fn test9() {
		check(&["\"", "'", r#"\\\" \"#]);
	}
}
