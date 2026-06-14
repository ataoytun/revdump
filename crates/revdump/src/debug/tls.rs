use windows_sys::Win32::Foundation::HANDLE;

use crate::nt;
use crate::reconstruct::pe::{self, PeView};

const MAX_CALLBACKS: usize = 256;

/// Read the static TLS callback addresses from the target's main image. Packers commonly run
/// unpack stubs through TLS callbacks *before* the entry point, so these must be tracked (and can
/// be breakpointed) — otherwise a pre-EP callback executing freshly-written memory could be
/// mistaken for the OEP.
pub fn callbacks(process: HANDLE, image_base: usize) -> Vec<usize> {
    let mut header = [0u8; 0x1000];
    if nt::read_memory(process, image_base, &mut header).unwrap_or(0) < 0x200 {
        return Vec::new();
    }
    let Some(view) = PeView::parse(&header) else {
        return Vec::new();
    };
    let ptr = if view.is_pe32_plus { 8 } else { 4 };

    let dd = view.opt + pe::data_directory_offset(view.is_pe32_plus, pe::DIR_TLS);
    let tls_rva = pe::read_u32(&header, dd).unwrap_or(0) as usize;
    if tls_rva == 0 {
        return Vec::new();
    }

    // AddressOfCallBacks is a VA pointing at a NULL-terminated array of callback VAs.
    let aoc_field = image_base + tls_rva + pe::TLS_ADDRESS_OF_CALLBACKS_INDEX * ptr;
    let array = match read_ptr(process, aoc_field, ptr) {
        Some(va) if va != 0 => va as usize,
        _ => return Vec::new(),
    };

    let mut out = Vec::new();
    let mut cursor = array;
    for _ in 0..MAX_CALLBACKS {
        match read_ptr(process, cursor, ptr) {
            Some(0) | None => break,
            Some(callback) => out.push(callback as usize),
        }
        cursor += ptr;
    }
    out
}

fn read_ptr(process: HANDLE, addr: usize, ptr: usize) -> Option<u64> {
    let mut buf = [0u8; 8];
    if nt::read_memory(process, addr, &mut buf[..ptr]).ok()? < ptr {
        return None;
    }
    Some(if ptr == 8 {
        u64::from_le_bytes(buf)
    } else {
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64
    })
}
