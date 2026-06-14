use std::collections::HashSet;

use crate::access::reader::{read_best_effort, MemoryReader, PAGE_SIZE};
use crate::discovery::peb::LoaderModule;
use crate::discovery::walk::{Region, RegionKind};
use crate::reconstruct::pe;

/// A PE image present in memory whose base isn't a loader module: manually-mapped / reflectively
/// loaded code the loader has no record of.
#[derive(Debug, Clone)]
pub struct HiddenModule {
    pub base: usize,
    pub size: usize,
    pub kind: RegionKind,
    pub is_pe32_plus: bool,
    pub mapped_path: Option<String>,
}

/// Executable private memory with no PE header: loose code (shellcode, JIT, unpacked stubs).
#[derive(Debug, Clone)]
pub struct CodeChunk {
    pub base: usize,
    pub size: usize,
    pub protect: u32,
}

pub fn find_hidden_modules<R: MemoryReader>(
    reader: &R,
    regions: &[Region],
    loader: &[LoaderModule],
) -> Vec<HiddenModule> {
    let loader_bases: HashSet<usize> = loader.iter().map(|m| m.base).collect();
    let mut seen = HashSet::new();
    let mut hidden = Vec::new();

    for region in regions {
        // One probe per allocation base; the PE header (if any) sits there.
        if region.alloc_base == 0 || !seen.insert(region.alloc_base) {
            continue;
        }
        if loader_bases.contains(&region.alloc_base) {
            continue;
        }
        let (head, _) = read_best_effort(reader, region.alloc_base, PAGE_SIZE);
        if let Some(info) = pe::parse_head(&head) {
            hidden.push(HiddenModule {
                base: region.alloc_base,
                size: info.size_of_image as usize,
                kind: region.kind,
                is_pe32_plus: info.is_pe32_plus,
                mapped_path: region.mapped_path.clone(),
            });
        }
    }
    hidden
}

pub fn find_loose_code(
    regions: &[Region],
    loader: &[LoaderModule],
    hidden: &[HiddenModule],
) -> Vec<CodeChunk> {
    regions
        .iter()
        .filter(|r| r.is_executable() && r.kind == RegionKind::Private)
        .filter(|r| !covered_by_module(r.base, loader, hidden))
        .map(|r| CodeChunk {
            base: r.base,
            size: r.size,
            protect: r.protect,
        })
        .collect()
}

fn covered_by_module(addr: usize, loader: &[LoaderModule], hidden: &[HiddenModule]) -> bool {
    loader
        .iter()
        .any(|m| addr >= m.base && addr < m.base.saturating_add(m.size))
        || hidden
            .iter()
            .any(|m| addr >= m.base && addr < m.base.saturating_add(m.size))
}
