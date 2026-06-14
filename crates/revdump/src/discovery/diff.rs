use goblin::pe::PE;

use crate::access::reader::{read_best_effort, MemoryReader};
use crate::discovery::peb::LoaderModule;
use crate::discovery::walk::{Region, RegionKind};
use crate::reconstruct::pe;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const REL_HIGHLOW: u16 = 3;
const REL_DIR64: u16 = 10;
// Cap per-module to keep output bounded; modified_bytes still reflects the full extent.
const MAX_HOOKS: usize = 64;

#[derive(Debug, Clone)]
pub struct Patch {
    pub rva: u32,
    pub len: u32,
}

/// Result of diffing one loaded module's in-memory image against its on-disk file.
#[derive(Debug, Clone)]
pub struct ModuleDiff {
    pub base: usize,
    pub name: String,
    /// Set when the loader's module name disagrees with the mapped file (hollowing/doppelganging).
    pub name_mismatch: Option<String>,
    pub image_base_mismatch: bool,
    pub header_modified: bool,
    pub hooks: Vec<Patch>,
    pub modified_bytes: usize,
    /// Why a module couldn't be fully diffed (file unreadable, parse failure, ...).
    pub note: Option<String>,
}

impl ModuleDiff {
    pub fn is_suspicious(&self) -> bool {
        self.is_hollowed() || !self.hooks.is_empty()
    }

    /// Hollowing-specific signals only (header/name/base replacement). Deliberately excludes
    /// inline hooks, which on modern Windows are dominated by benign loader import-optimization.
    pub fn is_hollowed(&self) -> bool {
        self.name_mismatch.is_some() || self.image_base_mismatch || self.header_modified
    }
}

pub fn diff_modules<R: MemoryReader>(
    reader: &R,
    regions: &[Region],
    loader: &[LoaderModule],
) -> Vec<ModuleDiff> {
    loader
        .iter()
        .map(|m| diff_module(reader, regions, m))
        .collect()
}

fn diff_module<R: MemoryReader>(
    reader: &R,
    regions: &[Region],
    module: &LoaderModule,
) -> ModuleDiff {
    let mut diff = ModuleDiff {
        base: module.base,
        name: module.base_name.clone(),
        name_mismatch: None,
        image_base_mismatch: false,
        header_modified: false,
        hooks: Vec::new(),
        modified_bytes: 0,
        note: None,
    };

    // Hollowing tell: the loader claims one name but the image section maps a different file.
    if let Some(mapped) = mapped_leaf(regions, module.base) {
        if !module.base_name.is_empty() && !mapped.eq_ignore_ascii_case(&module.base_name) {
            diff.name_mismatch = Some(mapped);
        }
    }

    let file = match std::fs::read(&module.full_name) {
        Ok(bytes) => bytes,
        Err(e) => {
            diff.note = Some(format!("on-disk file unreadable: {e}"));
            return diff;
        }
    };
    let pe = match PE::parse(&file) {
        Ok(pe) => pe,
        Err(e) => {
            diff.note = Some(format!("on-disk parse failed: {e}"));
            return diff;
        }
    };
    let Some(opt) = pe.header.optional_header else {
        diff.note = Some("on-disk image has no optional header".into());
        return diff;
    };

    let (mem_header, _) = read_best_effort(reader, module.base, 0x1000);
    if let (Some(mem), Some(disk)) = (pe::parse_head(&mem_header), pe::parse_head(&file)) {
        // The loader rewrites the in-memory ImageBase to the actual load base, so a value that
        // ISN'T the load base means the header was planted by something other than the loader
        // (hollowing). EP and section count the loader does not touch, so those diffs are genuine.
        diff.image_base_mismatch = mem.image_base != module.base as u64;
        diff.header_modified = mem.entry_point != disk.entry_point
            || mem.number_of_sections != disk.number_of_sections;
    }

    let Some(mut image) = build_disk_image(&file, &pe) else {
        diff.note = Some("could not lay out on-disk image".into());
        return diff;
    };

    // Relocate the disk copy to the live base so applied ASLR fixups don't read as modifications.
    let delta = module.base as i64 - opt.windows_fields.image_base as i64;
    if delta != 0 {
        if let Some(reloc) = opt.data_directories.get_base_relocation_table() {
            apply_relocations(
                &mut image,
                reloc.virtual_address as usize,
                reloc.size as usize,
                delta,
            );
        }
    }
    // The IAT is bound at load time; zero it in both copies so import binding isn't flagged.
    let iat = opt
        .data_directories
        .get_import_address_table()
        .map(|d| (d.virtual_address as usize, d.size as usize));

    // KNOWN LIMITATION: Windows 10+ applies "import optimization" and CFG patches to .text at
    // load time, so even a clean process shows small diffs here. They surface alongside genuine
    // inline hooks; telling them apart (e.g. a diff that rewrites an indirect import call into a
    // direct one) is left to downstream filtering (the clean-hash DB).
    for section in &pe.sections {
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let va = section.virtual_address as usize;
        let len = (section.virtual_size as usize).min(section.size_of_raw_data as usize);
        if len == 0 || va.saturating_add(len) > image.len() {
            continue;
        }
        let (mut mem_sec, _) = read_best_effort(reader, module.base + va, len);
        let disk_sec = &mut image[va..va + len];
        if let Some((iat_rva, iat_size)) = iat {
            zero_overlap(disk_sec, va, iat_rva, iat_size);
            zero_overlap(&mut mem_sec, va, iat_rva, iat_size);
        }
        collect_patches(va as u32, disk_sec, &mem_sec, &mut diff);
    }

    diff
}

fn mapped_leaf(regions: &[Region], base: usize) -> Option<String> {
    regions
        .iter()
        .find(|r| r.base == base && r.kind == RegionKind::Image)
        .and_then(|r| r.mapped_path.as_deref())
        .map(leaf_name)
}

fn leaf_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn build_disk_image(file: &[u8], pe: &PE) -> Option<Vec<u8>> {
    let opt = pe.header.optional_header?;
    let size_of_image = opt.windows_fields.size_of_image as usize;
    // Sanity bound: a corrupt SizeOfImage shouldn't make us allocate the world.
    if size_of_image == 0 || size_of_image > 0x8000_0000 {
        return None;
    }
    let mut image = vec![0u8; size_of_image];
    let headers = (opt.windows_fields.size_of_headers as usize)
        .min(file.len())
        .min(size_of_image);
    image[..headers].copy_from_slice(&file[..headers]);

    for s in &pe.sections {
        let va = s.virtual_address as usize;
        let raw = s.pointer_to_raw_data as usize;
        let rsize = s.size_of_raw_data as usize;
        if rsize == 0 {
            continue;
        }
        let copy = rsize
            .min(file.len().saturating_sub(raw))
            .min(size_of_image.saturating_sub(va));
        if copy == 0 {
            continue;
        }
        image[va..va + copy].copy_from_slice(&file[raw..raw + copy]);
    }
    Some(image)
}

fn apply_relocations(image: &mut [u8], reloc_rva: usize, reloc_size: usize, delta: i64) {
    let end = reloc_rva.saturating_add(reloc_size).min(image.len());
    let mut off = reloc_rva;
    while off + 8 <= end {
        let Some(page_rva) = pe::read_u32(image, off).map(|v| v as usize) else {
            break;
        };
        let Some(block_size) = pe::read_u32(image, off + 4).map(|v| v as usize) else {
            break;
        };
        if block_size < 8 {
            break;
        }
        for i in 0..(block_size - 8) / 2 {
            let Some(entry) = pe::read_u16(image, off + 8 + i * 2) else {
                break;
            };
            let patch = page_rva + (entry & 0x0FFF) as usize;
            match entry >> 12 {
                REL_HIGHLOW => {
                    if let Some(v) = pe::read_u32(image, patch) {
                        let nv = (v as i64).wrapping_add(delta) as u32;
                        image[patch..patch + 4].copy_from_slice(&nv.to_le_bytes());
                    }
                }
                REL_DIR64 => {
                    if let Some(v) = pe::read_u64(image, patch) {
                        let nv = (v as i64).wrapping_add(delta) as u64;
                        image[patch..patch + 8].copy_from_slice(&nv.to_le_bytes());
                    }
                }
                _ => {}
            }
        }
        off += block_size;
    }
}

// Zero the bytes of `buf` (which starts at RVA `buf_rva`) that fall inside [range_rva, +size).
fn zero_overlap(buf: &mut [u8], buf_rva: usize, range_rva: usize, range_size: usize) {
    let start = range_rva.max(buf_rva);
    let end = range_rva
        .saturating_add(range_size)
        .min(buf_rva + buf.len());
    if start < end {
        buf[start - buf_rva..end - buf_rva].fill(0);
    }
}

fn collect_patches(base_rva: u32, disk: &[u8], mem: &[u8], diff: &mut ModuleDiff) {
    let n = disk.len().min(mem.len());
    let mut i = 0;
    while i < n {
        if disk[i] == mem[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && disk[i] != mem[i] {
            i += 1;
        }
        let len = (i - start) as u32;
        diff.modified_bytes += len as usize;
        if diff.hooks.len() < MAX_HOOKS {
            diff.hooks.push(Patch {
                rva: base_rva + start as u32,
                len,
            });
        }
    }
}
