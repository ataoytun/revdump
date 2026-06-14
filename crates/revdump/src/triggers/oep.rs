use windows_sys::Win32::System::Memory::{
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY,
};

pub const EXCEPTION_ACCESS_VIOLATION: i32 = 0xC000_0005u32 as i32;

const PROTECTION_MASK: u32 = 0xFF; // low byte; PAGE_GUARD/PAGE_NOCACHE live in higher bits

pub fn is_executable(protect: u32) -> bool {
    matches!(
        protect & PROTECTION_MASK,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

/// Map an executable protection to its non-executable counterpart, preserving read/write so only
/// *execution* faults (DEP). That fault's address is the OEP.
pub fn strip_execute(protect: u32) -> u32 {
    match protect & PROTECTION_MASK {
        PAGE_EXECUTE | PAGE_EXECUTE_READ => PAGE_READONLY,
        PAGE_EXECUTE_READWRITE => PAGE_READWRITE,
        PAGE_EXECUTE_WRITECOPY => PAGE_WRITECOPY,
        other => other,
    }
}
