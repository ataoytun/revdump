use crate::reconstruct::exports::ExportCatalog;
use crate::reconstruct::pe::{self, PeView};

const ORDINAL_FLAG_32: u64 = 0x8000_0000;
const ORDINAL_FLAG_64: u64 = 0x8000_0000_0000_0000;
// A lone pointer that happens to equal an export address is almost always coincidence; require a
// contiguous run before treating it as an IAT block.
const MIN_RUN: usize = 2;

pub struct ImportRebuildStats {
    pub modules: usize,
    pub functions: usize,
}

enum Imp {
    Name(String),
    Ordinal(u16),
}

struct ResolvedEntry {
    rva: u32,
    module: String,
    imp: Imp,
}

struct Descriptor {
    module: String,
    first_thunk_rva: u32,
    imports: Vec<Imp>,
}

struct Idata {
    bytes: Vec<u8>,
    section_rva: u32,
    descriptor_table_size: u32,
}

/// Whether the image already advertises an import directory. A packer that erased it leaves this
/// at zero, which is the signal to reconstruct.
pub fn has_import_directory(image: &[u8]) -> bool {
    let Some(view) = PeView::parse(image) else {
        return false;
    };
    let dd = view.opt + pe::data_directory_offset(view.is_pe32_plus, pe::DIR_IMPORT);
    pe::read_u32(image, dd).unwrap_or(0) != 0
}

/// Locate the IAT by resolving pointer runs through `catalog`, then rebuild the import directory
/// into an appended `.idata` section whose FirstThunk points back at the existing IAT (so code
/// references stay valid) and whose INT carries the names. Returns `None` if nothing resolved.
pub fn rebuild_imports(image: &mut Vec<u8>, catalog: &ExportCatalog) -> Option<ImportRebuildStats> {
    let view = PeView::parse(image)?;
    let ptr = if view.is_pe32_plus { 8 } else { 4 };

    let descriptors = group(scan_iat(image, ptr, catalog));
    if descriptors.is_empty() {
        return None;
    }
    let stats = ImportRebuildStats {
        modules: descriptors.len(),
        functions: descriptors.iter().map(|d| d.imports.len()).sum(),
    };

    let idata = build_idata(&view, &descriptors, ptr)?;
    write_section(image, &view, idata)?;
    Some(stats)
}

fn read_ptr(image: &[u8], off: usize, ptr: usize) -> Option<u64> {
    if ptr == 8 {
        pe::read_u64(image, off)
    } else {
        pe::read_u32(image, off).map(u64::from)
    }
}

fn scan_iat(image: &[u8], ptr: usize, catalog: &ExportCatalog) -> Vec<Vec<ResolvedEntry>> {
    let mut runs = Vec::new();
    let mut current: Vec<ResolvedEntry> = Vec::new();
    let mut off = 0usize;
    while off + ptr <= image.len() {
        match read_ptr(image, off, ptr).and_then(|v| catalog.resolve(v)) {
            Some(export) => current.push(ResolvedEntry {
                rva: off as u32,
                module: export.module.clone(),
                imp: match &export.name {
                    Some(name) => Imp::Name(name.clone()),
                    None => Imp::Ordinal(export.ordinal),
                },
            }),
            None => take_run(&mut runs, &mut current),
        }
        off += ptr;
    }
    take_run(&mut runs, &mut current);
    runs
}

fn take_run(runs: &mut Vec<Vec<ResolvedEntry>>, current: &mut Vec<ResolvedEntry>) {
    if current.len() >= MIN_RUN {
        runs.push(std::mem::take(current));
    } else {
        current.clear();
    }
}

// Split each contiguous run into per-module descriptors (the IAT lays imports out module by
// module). Each descriptor's INT is null-terminated, so IDA names exactly that block.
fn group(runs: Vec<Vec<ResolvedEntry>>) -> Vec<Descriptor> {
    let mut descriptors = Vec::new();
    for run in runs {
        let mut it = run.into_iter().peekable();
        while let Some(first) = it.next() {
            let module = first.module.clone();
            let first_thunk_rva = first.rva;
            let mut imports = vec![first.imp];
            while it.peek().is_some_and(|e| e.module == module) {
                if let Some(e) = it.next() {
                    imports.push(e.imp);
                }
            }
            descriptors.push(Descriptor {
                module,
                first_thunk_rva,
                imports,
            });
        }
    }
    descriptors
}

fn build_idata(view: &PeView, descriptors: &[Descriptor], ptr: usize) -> Option<Idata> {
    let section_rva = pe::round_up(view.size_of_image, view.section_alignment);
    let desc_table_size = ((descriptors.len() + 1) * pe::IMPORT_DESCRIPTOR_SIZE) as u32;
    let int_region: u32 = descriptors
        .iter()
        .map(|d| ((d.imports.len() + 1) * ptr) as u32)
        .sum();
    let int_base = section_rva + desc_table_size;
    let strings_base = int_base + int_region;
    let ordinal_flag = if ptr == 8 {
        ORDINAL_FLAG_64
    } else {
        ORDINAL_FLAG_32
    };

    let mut int_bytes: Vec<u8> = Vec::new();
    let mut strings: Vec<u8> = Vec::new();
    let mut records: Vec<(u32, u32, u32)> = Vec::new(); // (OriginalFirstThunk, Name, FirstThunk)

    for d in descriptors {
        let oft_rva = int_base + int_bytes.len() as u32;
        let name_rva = strings_base + strings.len() as u32;
        strings.extend_from_slice(d.module.as_bytes());
        strings.push(0);

        for imp in &d.imports {
            let thunk = match imp {
                Imp::Name(name) => {
                    let rva = strings_base + strings.len() as u32;
                    strings.extend_from_slice(&[0, 0]); // Hint
                    strings.extend_from_slice(name.as_bytes());
                    strings.push(0);
                    if strings.len() % 2 == 1 {
                        strings.push(0); // keep IMAGE_IMPORT_BY_NAME word-aligned
                    }
                    u64::from(rva)
                }
                Imp::Ordinal(ordinal) => ordinal_flag | u64::from(*ordinal),
            };
            push_ptr(&mut int_bytes, thunk, ptr);
        }
        push_ptr(&mut int_bytes, 0, ptr); // INT null terminator
        records.push((oft_rva, name_rva, d.first_thunk_rva));
    }

    let mut bytes = Vec::new();
    for (oft, name, first_thunk) in &records {
        bytes.extend_from_slice(&oft.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        bytes.extend_from_slice(&0u32.to_le_bytes()); // ForwarderChain
        bytes.extend_from_slice(&name.to_le_bytes());
        bytes.extend_from_slice(&first_thunk.to_le_bytes());
    }
    bytes.extend_from_slice(&[0u8; pe::IMPORT_DESCRIPTOR_SIZE]); // null descriptor
    bytes.extend_from_slice(&int_bytes);
    bytes.extend_from_slice(&strings);

    Some(Idata {
        bytes,
        section_rva,
        descriptor_table_size: desc_table_size,
    })
}

fn push_ptr(buf: &mut Vec<u8>, value: u64, ptr: usize) {
    if ptr == 8 {
        buf.extend_from_slice(&value.to_le_bytes());
    } else {
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    }
}

fn write_section(image: &mut Vec<u8>, view: &PeView, idata: Idata) -> Option<()> {
    let new_sh = view.section_table + view.number_of_sections * pe::SECTION_HEADER_SIZE;
    let size_of_headers = pe::read_u32(image, view.opt + pe::OPT_SIZE_OF_HEADERS_OFFSET)? as usize;
    if new_sh + pe::SECTION_HEADER_SIZE > size_of_headers {
        return None; // no header slack for another section
    }

    let raw_size = pe::round_up(idata.bytes.len() as u32, view.section_alignment);
    if image.len() < idata.section_rva as usize {
        image.resize(idata.section_rva as usize, 0);
    }
    image.extend_from_slice(&idata.bytes);
    image.resize(idata.section_rva as usize + raw_size as usize, 0);

    // Memory-aligned section header (PointerToRawData == VirtualAddress).
    image[new_sh..new_sh + 8].copy_from_slice(b".idata\0\0");
    pe::write_u32(
        image,
        new_sh + pe::SEC_VIRTUAL_SIZE_OFFSET,
        idata.bytes.len() as u32,
    );
    pe::write_u32(
        image,
        new_sh + pe::SEC_VIRTUAL_ADDRESS_OFFSET,
        idata.section_rva,
    );
    pe::write_u32(image, new_sh + pe::SEC_SIZE_OF_RAW_DATA_OFFSET, raw_size);
    pe::write_u32(
        image,
        new_sh + pe::SEC_POINTER_TO_RAW_DATA_OFFSET,
        idata.section_rva,
    );
    pe::write_u32(
        image,
        new_sh + pe::SEC_CHARACTERISTICS_OFFSET,
        pe::SCN_CNT_INITIALIZED_DATA | pe::SCN_MEM_READ | pe::SCN_MEM_WRITE,
    );
    pe::write_u16(
        image,
        view.file_header + pe::FILE_NUMBER_OF_SECTIONS_OFFSET,
        (view.number_of_sections + 1) as u16,
    );

    let dd_import = view.opt + pe::data_directory_offset(view.is_pe32_plus, pe::DIR_IMPORT);
    pe::write_u32(image, dd_import, idata.section_rva);
    pe::write_u32(image, dd_import + 4, idata.descriptor_table_size);
    // The old bound-import directory is meaningless now; clear it so the loader ignores it.
    let dd_bound = view.opt + pe::data_directory_offset(view.is_pe32_plus, pe::DIR_BOUND_IMPORT);
    pe::write_u32(image, dd_bound, 0);
    pe::write_u32(image, dd_bound + 4, 0);

    // Recompute SizeOfImage now that the section is appended (SizeOfHeaders is unchanged).
    pe::write_u32(
        image,
        view.opt + pe::OPT_SIZE_OF_IMAGE_OFFSET,
        idata.section_rva + raw_size,
    );
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconstruct::exports::ExportRef;
    use crate::reconstruct::header;
    use goblin::pe::PE;

    #[test]
    fn rebuild_recovers_named_imports() {
        let va_a = 0x7fff_0000u64;
        let va_b = 0x7fff_0040u64;
        let catalog = ExportCatalog::from_entries(vec![
            (
                va_a,
                ExportRef {
                    module: "fake.dll".into(),
                    name: Some("FuncA".into()),
                    ordinal: 1,
                },
            ),
            (
                va_b,
                ExportRef {
                    module: "fake.dll".into(),
                    name: Some("FuncB".into()),
                    ordinal: 2,
                },
            ),
        ]);

        // .text holds an IAT [va_a, va_b, NULL] at native pointer width.
        let ptr = core::mem::size_of::<usize>();
        let mut code = Vec::new();
        push_ptr(&mut code, va_a, ptr);
        push_ptr(&mut code, va_b, ptr);
        push_ptr(&mut code, 0, ptr);
        let mut image = header::synthesize_pe(0x0040_0000, &code);

        assert!(!has_import_directory(&image));
        let stats = rebuild_imports(&mut image, &catalog).expect("should reconstruct imports");
        assert_eq!(stats.modules, 1);
        assert_eq!(stats.functions, 2);
        assert!(has_import_directory(&image));

        let pe = PE::parse(&image).expect("rebuilt PE must parse");
        let names: Vec<&str> = pe.imports.iter().map(|i| i.name.as_ref()).collect();
        assert!(names.contains(&"FuncA"), "imports were {names:?}");
        assert!(names.contains(&"FuncB"), "imports were {names:?}");
    }
}
