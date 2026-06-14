use core::mem::MaybeUninit;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT};
use windows_sys::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT};

use crate::error::{Result, RevError};

// CONTEXT_CONTROL = CONTEXT_<arch> | 1, the flag selecting the control registers (incl. the
// instruction pointer) for Get/SetThreadContext.
#[cfg(target_arch = "x86_64")]
const CONTEXT_CONTROL: u32 = 0x0010_0001;
#[cfg(target_arch = "x86")]
const CONTEXT_CONTROL: u32 = 0x0001_0001;

// x64 SetThreadContext requires the CONTEXT to be 16-byte aligned (it holds an XSAVE area); a
// plain stack CONTEXT is only 8-aligned. Force the alignment with a wrapper.
#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

/// Rewind a thread's instruction pointer to `ip`. Used after a software breakpoint fires: we
/// restore the original byte and point execution back at it so the real instruction re-runs.
pub fn set_instruction_pointer(tid: u32, ip: usize) -> Result<()> {
    // SAFETY: open the thread for context access, read+modify+write its control context through a
    // 16-byte-aligned buffer, then close the handle. ContextFlags is set before the read.
    unsafe {
        let thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, tid);
        if thread.is_null() {
            return Err(RevError::Access(format!("OpenThread({tid}) failed")));
        }

        let mut holder = MaybeUninit::<AlignedContext>::zeroed();
        let ctx = core::ptr::addr_of_mut!((*holder.as_mut_ptr()).0);
        (*ctx).ContextFlags = CONTEXT_CONTROL;
        if GetThreadContext(thread, ctx) == 0 {
            let gle = GetLastError();
            CloseHandle(thread);
            return Err(RevError::Access(format!(
                "GetThreadContext failed (GLE={gle})"
            )));
        }
        #[cfg(target_arch = "x86_64")]
        {
            (*ctx).Rip = ip as u64;
        }
        #[cfg(target_arch = "x86")]
        {
            (*ctx).Eip = ip as u32;
        }
        let ok = SetThreadContext(thread, ctx);
        let gle = GetLastError();
        CloseHandle(thread);
        if ok == 0 {
            return Err(RevError::Access(format!(
                "SetThreadContext failed (GLE={gle})"
            )));
        }
        Ok(())
    }
}
