//! Layer 3 — reconstruction. Turns captured process memory into IDA/Ghidra-loadable PE files:
//! section de-virtualization now, header synthesis and import rebuild in following commits.

pub mod devirt;
pub mod exports;
pub mod header;
pub mod imports;
pub mod pe;

use crate::access::reader::{read_best_effort, MemoryReader, PAGE_SIZE};
use crate::error::{Result, RevError};

pub struct DumpArtifact {
    pub bytes: Vec<u8>,
    pub base: usize,
    pub unreadable_pages: usize,
}

/// Dump a mapped image that still has intact headers: capture the whole in-memory image, then
/// memory-align the section table so it loads as the layout the loader/packer produced.
pub fn dump_module_image<R: MemoryReader>(reader: &R, base: usize) -> Result<DumpArtifact> {
    let (head, _) = read_best_effort(reader, base, PAGE_SIZE);
    let info = pe::parse_head(&head)
        .ok_or_else(|| RevError::Reconstruct(format!("no PE header at {base:#x}")))?;
    let (mut bytes, gaps) = read_best_effort(reader, base, info.size_of_image as usize);
    devirt::memory_align(&mut bytes)?;
    Ok(DumpArtifact {
        bytes,
        base,
        unreadable_pages: gaps.len(),
    })
}

/// Dump a headerless executable region (loose code, or a module whose header a packer erased) by
/// synthesizing a PE around the captured bytes.
pub fn dump_code_chunk<R: MemoryReader>(reader: &R, base: usize, size: usize) -> DumpArtifact {
    let (code, gaps) = read_best_effort(reader, base, size);
    DumpArtifact {
        bytes: header::synthesize_pe(base, &code),
        base,
        unreadable_pages: gaps.len(),
    }
}
