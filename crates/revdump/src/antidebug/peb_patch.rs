use core::mem::offset_of;

use windows_sys::Win32::Foundation::HANDLE;

use crate::error::Result;
use crate::nt;
use crate::nt::ffi::Peb;

// _PEB.ProcessHeap and _HEAP.Flags/ForceFlags offsets (stable on modern Windows 10/11).
#[cfg(target_pointer_width = "64")]
const PROCESS_HEAP_OFFSET: usize = 0x30;
#[cfg(target_pointer_width = "32")]
const PROCESS_HEAP_OFFSET: usize = 0x18;
#[cfg(target_pointer_width = "64")]
const HEAP_FLAGS_OFFSET: usize = 0x70;
#[cfg(target_pointer_width = "64")]
const HEAP_FORCE_FLAGS_OFFSET: usize = 0x74;
#[cfg(target_pointer_width = "32")]
const HEAP_FLAGS_OFFSET: usize = 0x40;
#[cfg(target_pointer_width = "32")]
const HEAP_FORCE_FLAGS_OFFSET: usize = 0x44;

const HEAP_GROWABLE: u32 = 0x0000_0002;
const PTR: usize = core::mem::size_of::<usize>();

/// Normalize the PEB/heap fields packers read to detect a debugger. Applied at the initial loader
/// breakpoint, which precedes the first TLS callback / the entry point only under --launch; on
/// attach it fires post-startup, so a pre-EP check may already have run.
pub fn neutralize(process: HANDLE, peb_base: usize) -> Result<()> {
    // BeingDebugged = 0 — what IsDebuggerPresent() returns.
    nt::write_memory(process, peb_base + offset_of!(Peb, being_debugged), &[0u8])?;
    // NtGlobalFlag = 0 — the FLG_HEAP_* debug bits a debugged process carries.
    nt::write_memory(
        process,
        peb_base + offset_of!(Peb, nt_global_flag),
        &0u32.to_le_bytes(),
    )?;

    // Heap Flags/ForceFlags: a debugged process gets extra validation bits set; reset to the clean
    // values. Best-effort — the heap struct offsets are version-dependent.
    if let Ok(heap) = read_ptr(process, peb_base + PROCESS_HEAP_OFFSET) {
        if heap != 0 {
            let _ = nt::write_memory(
                process,
                heap + HEAP_FLAGS_OFFSET,
                &HEAP_GROWABLE.to_le_bytes(),
            );
            let _ = nt::write_memory(process, heap + HEAP_FORCE_FLAGS_OFFSET, &0u32.to_le_bytes());
        }
    }
    Ok(())
}

fn read_ptr(process: HANDLE, addr: usize) -> Result<usize> {
    let mut buf = [0u8; PTR];
    nt::read_memory(process, addr, &mut buf)?;
    Ok(usize::from_le_bytes(buf))
}
