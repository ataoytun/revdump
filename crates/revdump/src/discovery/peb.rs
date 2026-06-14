use core::mem::offset_of;

use windows_sys::Win32::Foundation::HANDLE;

use crate::error::Result;
use crate::nt;
use crate::nt::ffi::{LdrDataTableEntry, PebLdrData, UnicodeString};

#[derive(Debug, Clone)]
pub struct LoaderModule {
    pub base: usize,
    pub size: usize,
    /// DOS path, e.g. C:\Windows\System32\ntdll.dll
    pub full_name: String,
    /// Leaf name, e.g. ntdll.dll
    pub base_name: String,
}

// Defensive cap: a corrupted/maliciously-cyclic loader list must not spin forever.
const MAX_MODULES: usize = 8192;

/// Enumerate loaded modules by walking PEB -> Ldr -> InLoadOrderModuleList straight out of target
/// memory, instead of trusting an API a packer may have hooked or loader fields it corrupted.
pub fn enumerate_loader_modules(process: HANDLE) -> Result<Vec<LoaderModule>> {
    let peb = nt::read_peb(process)?;
    let ldr_addr = peb.ldr as usize;
    if ldr_addr == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: PebLdrData is repr(C) POD; read_pod fills it from target bytes.
    let ldr: PebLdrData = unsafe { nt::read_pod(process, ldr_addr) }?;

    // The list head sits inside PEB_LDR_DATA. Each link points at an entry's InLoadOrderLinks,
    // which is at offset 0 of LDR_DATA_TABLE_ENTRY, so a link address IS the entry address.
    let head = ldr_addr + offset_of!(PebLdrData, in_load_order_module_list);

    let mut modules = Vec::new();
    let mut cursor = ldr.in_load_order_module_list.flink as usize;
    let mut steps = 0;
    while cursor != head && cursor != 0 && steps < MAX_MODULES {
        steps += 1;
        // SAFETY: LDR_DATA_TABLE_ENTRY is repr(C) POD; a bad read just ends the walk.
        let entry: LdrDataTableEntry = match unsafe { nt::read_pod(process, cursor) } {
            Ok(entry) => entry,
            Err(_) => break,
        };
        let base = entry.dll_base as usize;
        if base != 0 {
            modules.push(LoaderModule {
                base,
                size: entry.size_of_image as usize,
                full_name: read_unicode_string(process, &entry.full_dll_name),
                base_name: read_unicode_string(process, &entry.base_dll_name),
            });
        }
        cursor = entry.in_load_order_links.flink as usize;
    }
    Ok(modules)
}

fn read_unicode_string(process: HANDLE, s: &UnicodeString) -> String {
    let wchars = (s.length / 2) as usize;
    let buffer = s.buffer as usize;
    if wchars == 0 || buffer == 0 {
        return String::new();
    }
    let mut bytes = vec![0u8; wchars * 2];
    if nt::read_memory(process, buffer, &mut bytes).is_err() {
        return String::new();
    }
    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&utf16)
}
