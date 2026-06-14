//! Discovery layer: walk the address space, enumerate loader modules straight from the PEB, and
//! surface code the loader doesn't account for (manually-mapped modules, loose chunks). Diffing
//! each module's in-memory image against its on-disk file flags inline hooks and hollowing.

pub mod diff;
pub mod peb;
pub mod scan;
pub mod walk;

use windows_sys::Win32::Foundation::HANDLE;

use crate::access::reader::MemoryReader;
use crate::error::Result;
use diff::ModuleDiff;
use peb::LoaderModule;
use scan::{CodeChunk, HiddenModule};
use walk::Region;

pub struct DiscoveryReport {
    pub regions: Vec<Region>,
    pub loader_modules: Vec<LoaderModule>,
    pub hidden_modules: Vec<HiddenModule>,
    pub code_chunks: Vec<CodeChunk>,
    pub module_diffs: Vec<ModuleDiff>,
}

pub fn scan_process<R: MemoryReader>(process: HANDLE, reader: &R) -> Result<DiscoveryReport> {
    let regions = walk::enumerate_regions(process);
    let loader_modules = peb::enumerate_loader_modules(process)?;
    let hidden_modules = scan::find_hidden_modules(reader, &regions, &loader_modules);
    let code_chunks = scan::find_loose_code(&regions, &loader_modules, &hidden_modules);
    let module_diffs = diff::diff_modules(reader, &regions, &loader_modules);
    Ok(DiscoveryReport {
        regions,
        loader_modules,
        hidden_modules,
        code_chunks,
        module_diffs,
    })
}
