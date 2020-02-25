extern crate winapi;
extern crate ntapi;

use winapi::um::winnt::HANDLE;
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use winapi::um::processthreadsapi::OpenProcess;

use ntapi::ntpsapi::{
    NtQueryInformationProcess, PROCESS_BASIC_INFORMATION,
};

use std::mem::size_of;
use std::ptr::null_mut;

struct HandleWrapper
{
    handle : HANDLE,
}

impl Drop for HandleWrapper
{
    fn drop(&mut self)
    {
        unsafe { CloseHandle(self.handle); }
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
        Some(HandleWrapper{handle: process_handler})
    }
}

fn get_cmd_line(pid: DWORD) -> (Vec<String>, Vec<u16>) {
    use ntapi::ntpebteb::{PEB, PPEB};
    use ntapi::ntrtl::{PRTL_USER_PROCESS_PARAMETERS, RTL_USER_PROCESS_PARAMETERS};
    use winapi::shared::basetsd::SIZE_T;
    use winapi::um::memoryapi::ReadProcessMemory;

    unsafe {
        let mut res = Vec::new();

        let handle = match get_process_handler(pid) {
            Some(h) => h,
            None => return (res, vec![]),
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
            return (res, vec![]);
        }
        let pinfo = pinfo.assume_init();

        let ppeb: PPEB = pinfo.PebBaseAddress;
        let mut peb_copy = std::mem::MaybeUninit::<PEB>::uninit();
        if ReadProcessMemory(
            handle,
            ppeb as *mut _,
            peb_copy.as_mut_ptr() as *mut _,
            size_of::<PEB>() as SIZE_T,
            ::std::ptr::null_mut(),
        ) != TRUE
        {
            CloseHandle(handle);
            return (res, vec![]);
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
            ::std::ptr::null_mut(),
        ) != TRUE
        {
            return (res, vec![]);
        }
        let rtl_proc_param_copy = rtl_proc_param_copy.assume_init();

        let len = rtl_proc_param_copy.CommandLine.Length as usize;
        if len % 2 == 1
        {
            // Just in case, I don't know can it happen or not
            return (res, vec![]);
        }
        let len = len / 2;
        let mut buffer_copy: Vec<u16> = Vec::with_capacity(len);
        buffer_copy.set_len(len);
        if ReadProcessMemory(
            handle,
            rtl_proc_param_copy.CommandLine.Buffer as *mut _,
            buffer_copy.as_mut_ptr() as *mut _,
            len * 2  as SIZE_T,
            ::std::ptr::null_mut(),
        ) != TRUE
        {
            return (res, vec![]);
        }

        let cmdline = String::from_utf16_lossy(&buffer_copy);
        res.push(cmdline);   

        (res, buffer_copy)
    }
}

fn main()
{
    
}