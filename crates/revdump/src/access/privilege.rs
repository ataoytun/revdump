use core::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::error::{Result, RevError};

/// Enable SeDebugPrivilege on our own token. Returns whether the privilege is actually held
/// (a non-elevated process can ask successfully but still be denied it; that's not fatal, it
/// just means some targets won't open).
pub fn enable_se_debug() -> Result<bool> {
    // SAFETY: token handle is opened and closed locally; the privilege block is fully initialized
    // before the adjust call.
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(RevError::Privilege("OpenProcessToken failed".into()));
        }

        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let name = wide("SeDebugPrivilege");
        if LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return Err(RevError::Privilege(
                "LookupPrivilegeValueW(SeDebugPrivilege) failed".into(),
            ));
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let ok = AdjustTokenPrivileges(token, 0, &tp, 0, ptr::null_mut(), ptr::null_mut());
        // AdjustTokenPrivileges reports success even when it couldn't assign the privilege; the
        // real signal is ERROR_NOT_ALL_ASSIGNED in the last-error slot.
        let not_assigned = windows_sys::Win32::Foundation::GetLastError() == ERROR_NOT_ALL_ASSIGNED;
        CloseHandle(token);

        if ok == 0 {
            return Err(RevError::Privilege("AdjustTokenPrivileges failed".into()));
        }
        Ok(!not_assigned)
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}
