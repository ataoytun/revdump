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
            // A 32-bit (WOW64) target maps the 64-bit thunk layer as PE32+ images the 32-bit loader
            // list doesn't track. They are WOW64 support DLLs, not reflective code, so skip them.
            if cfg!(target_pointer_width = "32") && info.is_pe32_plus {
                if let Some(leaf) = region.mapped_path.as_deref().map(leaf_name) {
                    if is_wow64_support(leaf) {
                        continue;
                    }
                }
            }
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

// The 64-bit WOW64 thunk layer mapped into a 32-bit process: PE32+ images the 32-bit loader list
// doesn't track, but support DLLs rather than reflective code.
const WOW64_SUPPORT: [&str; 5] = [
    "wow64.dll",
    "wow64cpu.dll",
    "wow64win.dll",
    "wow64base.dll",
    "ntdll.dll",
];

fn is_wow64_support(leaf: &str) -> bool {
    WOW64_SUPPORT.iter().any(|m| leaf.eq_ignore_ascii_case(m))
}

fn leaf_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wow64_support_modules_are_recognized() {
        assert!(is_wow64_support("wow64cpu.dll"));
        assert!(is_wow64_support("WoW64.DLL"));
        assert!(is_wow64_support("ntdll.dll"));
        assert!(!is_wow64_support("kernel32.dll"));
        assert_eq!(
            leaf_name("\\Device\\HarddiskVolume3\\Windows\\System32\\wow64.dll"),
            "wow64.dll"
        );
    }
}
