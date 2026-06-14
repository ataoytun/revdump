use core::mem::MaybeUninit;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT};
use windows_sys::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT};

use crate::error::{Result, RevError};

// CONTEXT flag groups. CONTEXT_<arch> | bits: 1 = control (IP/SP/flags), 2 = integer registers.
#[cfg(target_arch = "x86_64")]
const CONTEXT_CONTROL: u32 = 0x0010_0001;
#[cfg(target_arch = "x86")]
const CONTEXT_CONTROL: u32 = 0x0001_0001;
#[cfg(target_arch = "x86_64")]
const CONTEXT_INTEGER: u32 = 0x0010_0002;

// x64 SetThreadContext requires the CONTEXT to be 16-byte aligned (it holds an XSAVE area); a
// plain stack CONTEXT is only 8-aligned. Force the alignment with a wrapper.
#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

fn open(tid: u32) -> Result<HANDLE> {
    // SAFETY: plain Win32 call; a null return signals failure.
    let thread = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, tid) };
    if thread.is_null() {
        return Err(RevError::Access(format!("OpenThread({tid}) failed")));
    }
    Ok(thread)
}

fn get(thread: HANDLE, flags: u32) -> Result<AlignedContext> {
    let mut holder = MaybeUninit::<AlignedContext>::zeroed();
    // SAFETY: ContextFlags is set before the read; the buffer is 16-aligned via AlignedContext.
    unsafe {
        let ctx = core::ptr::addr_of_mut!((*holder.as_mut_ptr()).0);
        (*ctx).ContextFlags = flags;
        if GetThreadContext(thread, ctx) == 0 {
            return Err(RevError::Access(format!(
                "GetThreadContext failed (GLE={})",
                GetLastError()
            )));
        }
        Ok(holder.assume_init())
    }
}

fn set(thread: HANDLE, ctx: &AlignedContext) -> Result<()> {
    // SAFETY: ctx is a fully-initialized, 16-aligned CONTEXT.
    if unsafe { SetThreadContext(thread, &ctx.0) } == 0 {
        return Err(RevError::Access(format!(
            "SetThreadContext failed (GLE={})",
            unsafe { GetLastError() }
        )));
    }
    Ok(())
}

/// Rewind a thread's instruction pointer to `ip` (after restoring a software breakpoint).
pub fn set_instruction_pointer(tid: u32, ip: usize) -> Result<()> {
    let thread = open(tid)?;
    let result = (|| {
        let mut ctx = get(thread, CONTEXT_CONTROL)?;
        #[cfg(target_arch = "x86_64")]
        {
            ctx.0.Rip = ip as u64;
        }
        #[cfg(target_arch = "x86")]
        {
            ctx.0.Eip = ip as u32;
        }
        set(thread, &ctx)
    })();
    // SAFETY: handle from OpenThread, owned here.
    unsafe { CloseHandle(thread) };
    result
}

/// Toggle the trap (single-step) flag so the next instruction raises STATUS_SINGLE_STEP — used to
/// step over a persistent breakpoint before re-arming it.
pub fn set_trap_flag(tid: u32, enabled: bool) -> Result<()> {
    const TRAP_FLAG: u32 = 0x100; // EFLAGS.TF
    let thread = open(tid)?;
    let result = (|| {
        let mut ctx = get(thread, CONTEXT_CONTROL)?;
        if enabled {
            ctx.0.EFlags |= TRAP_FLAG;
        } else {
            ctx.0.EFlags &= !TRAP_FLAG;
        }
        set(thread, &ctx)
    })();
    unsafe { CloseHandle(thread) };
    result
}

/// Read the first four integer call arguments (x64: RCX/RDX/R8/R9). Used by the OEP finder to
/// inspect a packer's VirtualProtect request.
#[cfg(target_arch = "x86_64")]
pub fn read_call_args(tid: u32) -> Result<[usize; 4]> {
    let thread = open(tid)?;
    let result = get(thread, CONTEXT_INTEGER).map(|ctx| {
        [
            ctx.0.Rcx as usize,
            ctx.0.Rdx as usize,
            ctx.0.R8 as usize,
            ctx.0.R9 as usize,
        ]
    });
    unsafe { CloseHandle(thread) };
    result
}

/// Overwrite the `index`-th integer call argument (x64), e.g. to strip execute off NewProtect.
#[cfg(target_arch = "x86_64")]
pub fn set_call_arg(tid: u32, index: usize, value: usize) -> Result<()> {
    let thread = open(tid)?;
    let result = (|| {
        let mut ctx = get(thread, CONTEXT_INTEGER)?;
        match index {
            0 => ctx.0.Rcx = value as u64,
            1 => ctx.0.Rdx = value as u64,
            2 => ctx.0.R8 = value as u64,
            3 => ctx.0.R9 = value as u64,
            _ => return Err(RevError::Access("call arg index out of range".into())),
        }
        set(thread, &ctx)
    })();
    unsafe { CloseHandle(thread) };
    result
}

// x86 (stdcall) passes these on the stack; the OEP finder's stack-argument support isn't built
// yet, so report it rather than silently misbehave.
#[cfg(not(target_arch = "x86_64"))]
pub fn read_call_args(_tid: u32) -> Result<[usize; 4]> {
    Err(RevError::Access(
        "VirtualProtect argument inspection is not implemented on x86".into(),
    ))
}

#[cfg(not(target_arch = "x86_64"))]
pub fn set_call_arg(_tid: u32, _index: usize, _value: usize) -> Result<()> {
    Err(RevError::Access(
        "VirtualProtect argument modification is not implemented on x86".into(),
    ))
}
