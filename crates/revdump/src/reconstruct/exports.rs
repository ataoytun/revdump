use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::access::reader::{read_best_effort, MemoryReader, PAGE_SIZE};
use crate::discovery::peb::LoaderModule;
use crate::reconstruct::pe::{self, PeView};

#[derive(Clone, Debug)]
pub struct ExportRef {
    pub module: String,
    pub name: Option<String>,
    pub ordinal: u16,
}

/// Maps an absolute export address to the (module, name/ordinal) it belongs to: the lookup that
/// turns a bound IAT pointer back into an import.
pub struct ExportCatalog {
    by_va: HashMap<u64, ExportRef>,
}

impl ExportCatalog {
    pub fn build<R: MemoryReader>(reader: &R, modules: &[LoaderModule]) -> Self {
        let mut scored: HashMap<u64, (u8, ExportRef)> = HashMap::new();
        for m in modules {
            parse_module(reader, m, &mut scored);
        }
        Self {
            by_va: scored.into_iter().map(|(va, (_, e))| (va, e)).collect(),
        }
    }

    pub fn resolve(&self, va: u64) -> Option<&ExportRef> {
        self.by_va.get(&va)
    }

    pub fn len(&self) -> usize {
        self.by_va.len()
    }

    #[cfg(test)]
    pub fn from_entries(entries: Vec<(u64, ExportRef)>) -> Self {
        Self {
            by_va: entries.into_iter().collect(),
        }
    }
}

// Disambiguate addresses exported by more than one module (forwarder aliases) by preferring the
// lowest-level provider, matching how the loader would resolve them.
fn priority(module: &str) -> u8 {
    match module.to_ascii_lowercase().as_str() {
        "ntdll.dll" => 4,
        "kernelbase.dll" => 3,
        "kernel32.dll" => 2,
        _ => 1,
    }
}

fn parse_module<R: MemoryReader>(
    reader: &R,
    m: &LoaderModule,
    out: &mut HashMap<u64, (u8, ExportRef)>,
) {
    let base = m.base;
    let (header, _) = read_best_effort(reader, base, PAGE_SIZE);
    let Some(view) = PeView::parse(&header) else {
        return;
    };

    let dd = view.opt + pe::data_directory_offset(view.is_pe32_plus, pe::DIR_EXPORT);
    let export_rva = pe::read_u32(&header, dd).unwrap_or(0) as usize;
    let export_size = pe::read_u32(&header, dd + 4).unwrap_or(0) as usize;
    if export_rva == 0 {
        return;
    }

    let mut dir = [0u8; 40];
    if reader.read(base + export_rva, &mut dir).unwrap_or(0) < dir.len() {
        return;
    }
    let ordinal_base = pe::read_u32(&dir, pe::EXPORT_ORDINAL_BASE_OFFSET).unwrap_or(0);
    let num_funcs = pe::read_u32(&dir, pe::EXPORT_NUMBER_OF_FUNCTIONS_OFFSET).unwrap_or(0) as usize;
    let num_names = pe::read_u32(&dir, pe::EXPORT_NUMBER_OF_NAMES_OFFSET).unwrap_or(0) as usize;
    let aof = pe::read_u32(&dir, pe::EXPORT_ADDRESS_OF_FUNCTIONS_OFFSET).unwrap_or(0) as usize;
    let aon = pe::read_u32(&dir, pe::EXPORT_ADDRESS_OF_NAMES_OFFSET).unwrap_or(0) as usize;
    let aono = pe::read_u32(&dir, pe::EXPORT_ADDRESS_OF_NAME_ORDINALS_OFFSET).unwrap_or(0) as usize;
    // Guard against corrupt directories steering us into huge allocations.
    if num_funcs == 0 || num_funcs > 0x40000 || num_names > num_funcs {
        return;
    }

    let (funcs, _) = read_best_effort(reader, base + aof, num_funcs * 4);
    let (names, _) = read_best_effort(reader, base + aon, num_names * 4);
    let (ords, _) = read_best_effort(reader, base + aono, num_names * 2);

    // Build function-index -> name from the parallel name/ordinal arrays.
    let mut name_by_index: HashMap<usize, String> = HashMap::new();
    for k in 0..num_names {
        let name_rva = pe::read_u32(&names, k * 4).unwrap_or(0) as usize;
        let func_index = pe::read_u16(&ords, k * 2).unwrap_or(0) as usize;
        if name_rva != 0 {
            let name = read_c_string(reader, base + name_rva);
            if !name.is_empty() {
                name_by_index.insert(func_index, name);
            }
        }
    }

    let prio = priority(&m.base_name);
    for i in 0..num_funcs {
        let func_rva = pe::read_u32(&funcs, i * 4).unwrap_or(0) as usize;
        if func_rva == 0 {
            continue;
        }
        // A function RVA inside the export directory is a forwarder string, not real code; the IAT
        // points at the final target instead, so skip it here.
        if func_rva >= export_rva && func_rva < export_rva + export_size {
            continue;
        }
        let va = (base + func_rva) as u64;
        let entry = ExportRef {
            module: m.base_name.clone(),
            name: name_by_index.get(&i).cloned(),
            ordinal: ordinal_base.wrapping_add(i as u32) as u16,
        };
        match out.entry(va) {
            Entry::Occupied(mut o) => {
                if prio > o.get().0 {
                    o.insert((prio, entry));
                }
            }
            Entry::Vacant(v) => {
                v.insert((prio, entry));
            }
        }
    }
}

fn read_c_string<R: MemoryReader>(reader: &R, addr: usize) -> String {
    let mut buf = [0u8; 256];
    let n = reader.read(addr, &mut buf).unwrap_or(0);
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    String::from_utf8_lossy(&buf[..end]).into_owned()
}
