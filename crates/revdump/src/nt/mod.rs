//! Safe wrappers over the NTAPI surface in [`ffi`]. Callers stay in safe Rust; the `unsafe` is
//! confined here and at the FFI declarations.

pub mod ffi;

use core::ffi::c_void;
use core::mem::{size_of, MaybeUninit};

use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};

use crate::error::{Result, RevError};
use ffi::{
    nt_success, NtQueryInformationProcess, NtReadVirtualMemory, NtWriteVirtualMemory, Peb,
    ProcessBasicInformation, PsProtection, PROCESS_BASIC_INFORMATION_CLASS,
    PROCESS_PROTECTION_INFORMATION, STATUS_PARTIAL_COPY,
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
