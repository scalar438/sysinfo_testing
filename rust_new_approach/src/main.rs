extern crate ntapi;
extern crate winapi;

use std::mem::MaybeUninit;

use winapi::shared::minwindef::{DWORD, FALSE, ULONG};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, UNICODE_STRING};
use winapi::shared::ntstatus::{
	STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH,
};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;

use ntapi::ntpsapi::{NtQueryInformationProcess, ProcessCommandLineInformation, PROCESSINFOCLASS};

unsafe fn create_unicode_string(p: *const UNICODE_STRING) -> String {
	let slice = std::slice::from_raw_parts((*p).Buffer, (*p).Length as usize / 2);
	String::from_utf16_lossy(slice)
}

unsafe fn PhpQueryProcessVariableSize(
	ProcessHandle: HANDLE,
	ProcessInformationClass: PROCESSINFOCLASS,
) -> Result<Vec<String>, NTSTATUS> {
	let mut returnLength: ULONG = 0;

	let mut status = NtQueryInformationProcess(
		ProcessHandle,
		ProcessInformationClass,
		std::ptr::null_mut(),
		0,
		&mut returnLength as *mut _,
	);

	if (status != STATUS_BUFFER_OVERFLOW
		&& status != STATUS_BUFFER_TOO_SMALL
		&& status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return Err(status);
	}

	let buf_len = (returnLength as usize) / 2;
	let mut buffer: Vec<u16> = Vec::with_capacity(buf_len + 1);
	buffer.set_len(buf_len);

	status = NtQueryInformationProcess(
		ProcessHandle,
		ProcessInformationClass,
		buffer.as_mut_ptr() as *mut _,
		returnLength,
		&mut returnLength as *mut _,
	);
	let buffer = (*(buffer.as_ptr() as *const UNICODE_STRING)).Buffer;

	// Get argc and argv from command line
	let mut argc = MaybeUninit::<i32>::uninit();
	let argv_p = winapi::um::shellapi::CommandLineToArgvW(buffer as *const _, argc.as_mut_ptr());
	if argv_p.is_null() {
		return Ok(Vec::new());
	}
	let argc = argc.assume_init();
	let argv = std::slice::from_raw_parts(argv_p, argc as usize);

	let mut res = Vec::new();
	for arg in argv {
		let len = libc::wcslen(*arg);
		let str_slice = std::slice::from_raw_parts(*arg, len);
		res.push(String::from_utf16_lossy(str_slice));
	}
	winapi::um::winbase::LocalFree(argv_p as *mut _);

	return Ok(res);
}

fn get_cmd_line(h: HANDLE) -> Vec<String> {
	if let Ok(v) = unsafe { PhpQueryProcessVariableSize(h, ProcessCommandLineInformation) } {
		v
	} else {
		vec![]
	}
}

fn main() {
	let pid;
	{
		let mut input = String::new();
		std::io::stdin().read_line(&mut input).unwrap();
		pid = input.trim().parse().unwrap();
	}
	let options = PROCESS_QUERY_INFORMATION;
	let process_handler = unsafe { OpenProcess(options, FALSE, pid) };
	let argv = get_cmd_line(process_handler);
	print!("{}", argv.join(" "));
	std::thread::sleep(std::time::Duration::from_secs(1));
}
