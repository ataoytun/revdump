//! Safe wrappers over the NTAPI surface in [`ffi`]. Callers stay in safe Rust; the `unsafe` is
//! confined here and at the FFI declarations.

pub mod ffi;

use core::ffi::c_void;
use core::mem::{size_of, MaybeUninit};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::error::{Result, RevError};
use ffi::{
    nt_success, NtQueryInformationProcess, NtReadVirtualMemory, NtWriteVirtualMemory, Peb,
    ProcessBasicInformation, PsProtection, PROCESS_BASIC_INFORMATION_CLASS,
    PROCESS_PROTECTION_INFORMATION, PROCESS_WOW64_INFORMATION, STATUS_PARTIAL_COPY,
};

fn nt_check(call: &'static str, status: NTSTATUS) -> Result<()> {
    if nt_success(status) {
        Ok(())
    } else {
        Err(RevError::Nt {
            call,
            status: status as u32,
        })
    }
}

/// Read into `buf`, returning the count actually read. A guarded/partial region yields
/// STATUS_PARTIAL_COPY, which we report as a short read rather than an error so callers can
/// fall back to page-granular reads.
pub fn read_memory(process: HANDLE, addr: usize, buf: &mut [u8]) -> Result<usize> {
    let mut read = 0usize;
    // SAFETY: ntdll writes at most buf.len() bytes into our buffer and sets `read`.
    let status = unsafe {
        NtReadVirtualMemory(
            process,
            addr as *const c_void,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut read,
        )
    };
    if nt_success(status) || status == STATUS_PARTIAL_COPY {
        Ok(read)
    } else {
        Err(RevError::Nt {
            call: "NtReadVirtualMemory",
            status: status as u32,
        })
    }
}

/// Read a plain-old-data `T` out of the target.
///
/// # Safety
/// `T` must be valid for any bit pattern (no padding invariants, no references) — it is filled
/// from raw target bytes. The NT structs in [`ffi`] satisfy this.
pub unsafe fn read_pod<T: Copy>(process: HANDLE, addr: usize) -> Result<T> {
    let mut value = MaybeUninit::<T>::uninit();
    let buf = core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size_of::<T>());
    let n = read_memory(process, addr, buf)?;
    if n != size_of::<T>() {
        return Err(RevError::Access(format!(
            "short read at {addr:#x}: {n}/{} bytes",
            size_of::<T>()
        )));
    }
    Ok(value.assume_init())
}

pub fn query_basic_information(process: HANDLE) -> Result<ProcessBasicInformation> {
    let mut pbi = MaybeUninit::<ProcessBasicInformation>::uninit();
    let mut ret = 0u32;
    // SAFETY: out-buffer is sized exactly to the struct; ntdll fills it on success.
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            PROCESS_BASIC_INFORMATION_CLASS,
            pbi.as_mut_ptr().cast(),
            size_of::<ProcessBasicInformation>() as u32,
            &mut ret,
        )
    };
    nt_check("NtQueryInformationProcess(ProcessBasicInformation)", status)?;
    // SAFETY: success above means the struct was fully written.
    Ok(unsafe { pbi.assume_init() })
}

/// PS_PROTECTION of the target, used to recognize PP/PPL processes we cannot dump.
pub fn query_protection(process: HANDLE) -> Result<PsProtection> {
    let mut prot = PsProtection(0);
    let mut ret = 0u32;
    // SAFETY: the class returns a single byte; the buffer is one byte.
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            PROCESS_PROTECTION_INFORMATION,
            (&mut prot as *mut PsProtection).cast(),
            size_of::<PsProtection>() as u32,
            &mut ret,
        )
    };
    nt_check(
        "NtQueryInformationProcess(ProcessProtectionInformation)",
        status,
    )?;
    Ok(prot)
}

pub fn write_memory(process: HANDLE, addr: usize, data: &[u8]) -> Result<()> {
    let mut written = 0usize;
    // SAFETY: ntdll writes data.len() bytes from our buffer into the target.
    let status = unsafe {
        NtWriteVirtualMemory(
            process,
            addr as *mut c_void,
            data.as_ptr().cast(),
            data.len(),
            &mut written,
        )
    };
    nt_check("NtWriteVirtualMemory", status)?;
    if written != data.len() {
        return Err(RevError::Access(format!(
            "short write at {addr:#x}: {written}/{} bytes",
            data.len()
        )));
    }
    Ok(())
}

pub fn peb_base(process: HANDLE) -> Result<usize> {
    Ok(query_basic_information(process)?.peb_base_address as usize)
}

pub fn read_peb(process: HANDLE) -> Result<Peb> {
    let base = peb_base(process)?;
    // SAFETY: Peb is repr(C) POD; read_pod fills it from target bytes.
    unsafe { read_pod::<Peb>(process, base) }
}

/// Whether `process` is a 32-bit process running under WOW64. ProcessWow64Information returns the
/// target's PEB32 address (nonzero) for a WOW64 process, 0 for a native one.
pub fn is_wow64(process: HANDLE) -> Result<bool> {
    let mut wow64_peb: usize = 0;
    let mut ret = 0u32;
    // SAFETY: the class writes a single pointer-sized value into our buffer.
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            PROCESS_WOW64_INFORMATION,
            (&mut wow64_peb as *mut usize).cast(),
            size_of::<usize>() as u32,
            &mut ret,
        )
    };
    nt_check("NtQueryInformationProcess(ProcessWow64Information)", status)?;
    Ok(wow64_peb != 0)
}

// Whether *we* run under WOW64 (32-bit build on a 64-bit OS). Queried once for the lifetime of the
// process; unwrap_or(false) keeps this infallible so it stays clean under deny(clippy::unwrap_used).
fn self_is_wow64() -> bool {
    static SELF_WOW64: OnceLock<bool> = OnceLock::new();
    // SAFETY: GetCurrentProcess returns a pseudo-handle valid for the query.
    *SELF_WOW64.get_or_init(|| is_wow64(unsafe { GetCurrentProcess() }).unwrap_or(false))
}

// Pure bitness decision, factored out so the per-arch rule is unit-testable without a live handle.
// Returns the refusal reason, or None if the target is dumpable by this build.
fn arch_mismatch_reason(
    build64: bool,
    self_wow64: bool,
    target_wow64: bool,
) -> Option<&'static str> {
    if build64 {
        // revdump64 dumps native 64-bit targets; a WOW64 target is 32-bit.
        target_wow64.then_some("target is 32-bit (WOW64); use revdump32")
    } else if self_wow64 {
        // revdump32 on a 64-bit OS: a non-WOW64 target is native 64-bit.
        (!target_wow64).then_some("target is 64-bit; use revdump64")
    } else {
        // 32-bit OS: every process is 32-bit — nothing to refuse.
        None
    }
}

/// Refuse a cross-bitness target up front, enforcing the build-time arch lock at runtime: dumping a
/// foreign-bitness PEB/LDR would silently yield import-less, mis-classified output.
pub fn verify_dumpable_arch(process: HANDLE) -> Result<()> {
    let build64 = cfg!(target_pointer_width = "64");
    let self_wow64 = !build64 && self_is_wow64();
    let target_wow64 = is_wow64(process)?;
    match arch_mismatch_reason(build64, self_wow64, target_wow64) {
        Some(reason) => Err(RevError::ArchMismatch(reason.into())),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::arch_mismatch_reason;

    #[test]
    fn arch_decision_table() {
        // revdump64: dump native 64-bit, refuse 32-bit (WOW64).
        assert!(arch_mismatch_reason(true, false, false).is_none());
        assert!(arch_mismatch_reason(true, false, true).is_some());

        // revdump32 on a 64-bit OS (self is WOW64): dump 32-bit (WOW64), refuse native 64-bit.
        assert!(arch_mismatch_reason(false, true, true).is_none());
        assert!(arch_mismatch_reason(false, true, false).is_some());

        // revdump32 on a 32-bit OS (self not WOW64): every process is 32-bit, never refuse.
        assert!(arch_mismatch_reason(false, false, false).is_none());
        assert!(arch_mismatch_reason(false, false, true).is_none());
    }
}
