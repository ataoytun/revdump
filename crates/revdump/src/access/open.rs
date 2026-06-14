use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED, HANDLE};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
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
    // SAFETY: plain Win32 call; a null return signals failure.
    let handle = unsafe { OpenProcess(desired, 0, pid) };
    if !handle.is_null() {
        return Ok(OwnedProcess { handle });
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
    // SAFETY: plain Win32 call; null signals failure.
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

fn describe_protection(p: PsProtection) -> String {
    let kind = match p.protection_type() {
        1 => "PPL",
        2 => "PP",
        other => return format!("protected (type {other})"),
    };
    format!("{kind}, signer {}", p.signer())
}
