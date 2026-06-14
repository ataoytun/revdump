use core::ffi::c_void;
use core::ptr;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{GetLastError, HANDLE};

use crate::error::{Result, RevError};

// windows-sys doesn't surface MiniDumpWriteDump under our feature set, so declare it directly
// against dbghelp (a documented API; the SDK ships dbghelp.lib).
#[link(name = "dbghelp")]
extern "system" {
    fn MiniDumpWriteDump(
        process: HANDLE,
        process_id: u32,
        file: HANDLE,
        dump_type: u32,
        exception_param: *const c_void,
        user_stream_param: *const c_void,
        callback_param: *const c_void,
    ) -> i32;
}

const MINIDUMP_WITH_FULL_MEMORY: u32 = 0x0000_0002;

/// Write a full-memory minidump (.dmp) of the target — the classic crash-dump format, kept
/// separate from the RE-oriented PE dumps. The target must be open with VM_READ +
/// QUERY_INFORMATION, which is what `open_process` grants.
pub fn write_minidump(process: HANDLE, pid: u32, path: &Path) -> Result<()> {
    let file = File::create(path)?;
    let file_handle = file.as_raw_handle() as HANDLE;

    // SAFETY: valid process + file handles; the three optional info params are null.
    let ok = unsafe {
        MiniDumpWriteDump(
            process,
            pid,
            file_handle,
            MINIDUMP_WITH_FULL_MEMORY,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    if ok == 0 {
        let gle = unsafe { GetLastError() };
        return Err(RevError::Output(format!(
            "MiniDumpWriteDump failed (GLE={gle})"
        )));
    }
    Ok(())
}
