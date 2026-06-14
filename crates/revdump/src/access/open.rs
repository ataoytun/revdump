use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED, HANDLE};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

use crate::error::{Result, RevError};
use crate::nt;
use crate::nt::ffi::PsProtection;

/// A process handle that closes itself on drop.
pub struct OwnedProcess {
    handle: HANDLE,
}

impl OwnedProcess {
    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        // SAFETY: handle came from OpenProcess and is owned exclusively by this value.
        unsafe { CloseHandle(self.handle) };
    }
}

/// Open a target for querying + reading. On access-denied, probe for PP/PPL so the caller can
/// print a clean "protected" message instead of a bare access error.
pub fn open_process(pid: u32) -> Result<OwnedProcess> {
    let desired = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    // SAFETY: OpenProcess takes no buffers we own; it returns a handle or null, checked below.
    let handle = unsafe { OpenProcess(desired, 0, pid) };
    if !handle.is_null() {
        let proc = OwnedProcess { handle };
        // Refuse a cross-bitness target before any PEB-dependent read (drops the handle on error).
        nt::verify_dumpable_arch(proc.handle())?;
        return Ok(proc);
    }

    // SAFETY: read the thread-local last-error immediately after the failed call.
    let gle = unsafe { GetLastError() };
    if gle == ERROR_ACCESS_DENIED {
        if let Some(level) = probe_protection(pid) {
            return Err(RevError::Protected(level));
        }
    }
    Err(RevError::Access(format!(
        "OpenProcess(pid={pid}) failed (GLE={gle})"
    )))
}

// PROCESS_QUERY_LIMITED_INFORMATION is grantable on many targets that deny the heavier rights,
// which is enough to read PS_PROTECTION and tell PPL apart from a plain access denial.
fn probe_protection(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess for the protection probe; null means even the limited query was denied.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let guard = OwnedProcess { handle };
    match nt::query_protection(guard.handle()) {
        Ok(p) if p.is_protected() => Some(describe_protection(p)),
        _ => None,
    }
}

/// The leaf image name of `pid` (e.g. "notepad.exe"), for the `-p` name-regex scope. Uses
/// PROCESS_QUERY_LIMITED_INFORMATION, grantable on most targets that deny the heavier read rights,
/// so the match set isn't limited to processes we could already fully open.
pub fn image_base_name(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess for the name query; null means the pid is gone or access-denied.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let guard = OwnedProcess { handle };
    let mut buf = [0u16; 260]; // MAX_PATH
    let mut len = buf.len() as u32;
    // SAFETY: QueryFullProcessImageNameW writes up to `len` UTF-16 units and updates `len`. Flag 0
    // = Win32 path format.
    let ok = unsafe { QueryFullProcessImageNameW(guard.handle(), 0, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return None;
    }
    let full = String::from_utf16_lossy(&buf[..len as usize]);
    Some(full.rsplit(['\\', '/']).next().unwrap_or(&full).to_string())
}

fn describe_protection(p: PsProtection) -> String {
    let kind = match p.protection_type() {
        1 => "PPL",
        2 => "PP",
        other => return format!("protected (type {other})"),
    };
    format!("{kind}, signer {}", p.signer())
}
