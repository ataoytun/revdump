//! PE format constants and small header readers: the single source of truth for offsets and flags
//! shared across discovery and reconstruction. Nothing here duplicates an offset defined elsewhere.

pub const DOS_MAGIC: [u8; 2] = *b"MZ";
pub const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";

pub const DOS_E_LFANEW_OFFSET: usize = 0x3C;
/// IMAGE_FILE_HEADER size; the optional header follows it (after the 4-byte PE signature).
pub const FILE_HEADER_SIZE: usize = 20;
pub const OPTIONAL_HEADER_OFFSET_FROM_PE_SIG: usize = 4 + FILE_HEADER_SIZE;

pub const OPT_MAGIC_PE32: u16 = 0x10B;
pub const OPT_MAGIC_PE32PLUS: u16 = 0x20B;

// IMAGE_FILE_HEADER field offsets (from the start of the file header).
pub const FILE_NUMBER_OF_SECTIONS_OFFSET: usize = 0x02;

// IMAGE_OPTIONAL_HEADER field offsets (identical for PE32 / PE32+ except ImageBase).
pub const OPT_MAGIC_OFFSET: usize = 0x00;
pub const OPT_ADDRESS_OF_ENTRY_POINT_OFFSET: usize = 0x10;
pub const OPT_SIZE_OF_IMAGE_OFFSET: usize = 0x38;
pub const OPT_SECTION_ALIGNMENT_OFFSET: usize = 0x20;
pub const OPT_FILE_ALIGNMENT_OFFSET: usize = 0x24;
pub const OPT_SIZE_OF_HEADERS_OFFSET: usize = 0x3C;
// ImageBase is a 4-byte field at 0x1C on PE32, an 8-byte field at 0x18 on PE32+.
pub const OPT_IMAGE_BASE_OFFSET_PE32: usize = 0x1C;
pub const OPT_IMAGE_BASE_OFFSET_PE32PLUS: usize = 0x18;
pub const FILE_SIZE_OF_OPTIONAL_HEADER_OFFSET: usize = 0x10;

// IMAGE_SECTION_HEADER: 40 bytes, field offsets from the start of each entry.
pub const SECTION_HEADER_SIZE: usize = 40;
pub const SEC_VIRTUAL_SIZE_OFFSET: usize = 0x08;
pub const SEC_VIRTUAL_ADDRESS_OFFSET: usize = 0x0C;
pub const SEC_SIZE_OF_RAW_DATA_OFFSET: usize = 0x10;
pub const SEC_POINTER_TO_RAW_DATA_OFFSET: usize = 0x14;

// Values used when synthesizing headers from scratch.
pub const MACHINE_I386: u16 = 0x014C;
pub const MACHINE_AMD64: u16 = 0x8664;
pub const FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const SUBSYSTEM_WINDOWS_CUI: u16 = 3;
pub const SCN_CNT_CODE: u32 = 0x0000_0020;
pub const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;
pub const SEC_CHARACTERISTICS_OFFSET: usize = 0x24;

// Data directories (index into the optional header's directory array).
pub const OPT_DATA_DIRECTORY_OFFSET_PE32: usize = 0x60;
pub const OPT_DATA_DIRECTORY_OFFSET_PE32PLUS: usize = 0x70;
pub const DATA_DIRECTORY_ENTRY_SIZE: usize = 8;
pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_TLS: usize = 9;
pub const DIR_BOUND_IMPORT: usize = 11;

// IMAGE_TLS_DIRECTORY: AddressOfCallBacks is the 4th pointer-sized field (a VA to a
// NULL-terminated array of callback VAs).
pub const TLS_ADDRESS_OF_CALLBACKS_INDEX: usize = 3;

pub const fn data_directory_offset(pe32_plus: bool, index: usize) -> usize {
    let base = if pe32_plus {
        OPT_DATA_DIRECTORY_OFFSET_PE32PLUS
    } else {
        OPT_DATA_DIRECTORY_OFFSET_PE32
    };
    base + index * DATA_DIRECTORY_ENTRY_SIZE
}

// IMAGE_EXPORT_DIRECTORY field offsets.
pub const EXPORT_NAME_OFFSET: usize = 0x0C;
pub const EXPORT_ORDINAL_BASE_OFFSET: usize = 0x10;
pub const EXPORT_NUMBER_OF_FUNCTIONS_OFFSET: usize = 0x14;
pub const EXPORT_NUMBER_OF_NAMES_OFFSET: usize = 0x18;
pub const EXPORT_ADDRESS_OF_FUNCTIONS_OFFSET: usize = 0x1C;
pub const EXPORT_ADDRESS_OF_NAMES_OFFSET: usize = 0x20;
pub const EXPORT_ADDRESS_OF_NAME_ORDINALS_OFFSET: usize = 0x24;

pub const IMPORT_DESCRIPTOR_SIZE: usize = 20;

pub const fn machine_for(pe32_plus: bool) -> u16 {
    if pe32_plus {
        MACHINE_AMD64
    } else {
        MACHINE_I386
    }
}

/// Header facts read out of an image's first page (in-memory or on-disk).
#[derive(Debug, Clone, Copy)]
pub struct PeHead {
    pub is_pe32_plus: bool,
    pub size_of_image: u32,
    pub entry_point: u32,
    pub image_base: u64,
    pub number_of_sections: u16,
}

/// Parse just enough of the PE headers to identify an image and learn its size/base/entry.
/// Returns `None` if the buffer doesn't hold a valid MZ/PE header prefix.
pub fn parse_head(buf: &[u8]) -> Option<PeHead> {
    if buf.get(..2)? != DOS_MAGIC {
        return None;
    }
    let e_lfanew = read_u32(buf, DOS_E_LFANEW_OFFSET)? as usize;
    if buf.get(e_lfanew..e_lfanew + 4)? != PE_SIGNATURE {
        return None;
    }
    let opt = e_lfanew + OPTIONAL_HEADER_OFFSET_FROM_PE_SIG;
    let magic = read_u16(buf, opt + OPT_MAGIC_OFFSET)?;
    let is_pe32_plus = match magic {
        OPT_MAGIC_PE32PLUS => true,
        OPT_MAGIC_PE32 => false,
        _ => return None,
    };
    let image_base = if is_pe32_plus {
        read_u64(buf, opt + OPT_IMAGE_BASE_OFFSET_PE32PLUS)?
    } else {
        read_u32(buf, opt + OPT_IMAGE_BASE_OFFSET_PE32)? as u64
    };
    Some(PeHead {
        is_pe32_plus,
        size_of_image: read_u32(buf, opt + OPT_SIZE_OF_IMAGE_OFFSET)?,
        entry_point: read_u32(buf, opt + OPT_ADDRESS_OF_ENTRY_POINT_OFFSET)?,
        image_base,
        number_of_sections: read_u16(buf, e_lfanew + 4 + FILE_NUMBER_OF_SECTIONS_OFFSET)?,
    })
}

pub fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

pub fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    let b = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

pub fn write_u32(buf: &mut [u8], off: usize, val: u32) -> bool {
    match buf.get_mut(off..off + 4) {
        Some(slot) => {
            slot.copy_from_slice(&val.to_le_bytes());
            true
        }
        None => false,
    }
}

pub fn write_u16(buf: &mut [u8], off: usize, val: u16) -> bool {
    match buf.get_mut(off..off + 2) {
        Some(slot) => {
            slot.copy_from_slice(&val.to_le_bytes());
            true
        }
        None => false,
    }
}

pub fn round_up(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    value.div_ceil(align).saturating_mul(align)
}

/// Located header positions plus the layout fields the reconstructor needs to rewrite. Carries
/// more of the header than [`PeHead`], which only identifies an image.
#[derive(Debug, Clone, Copy)]
pub struct PeView {
    pub opt: usize,
    pub file_header: usize,
    pub is_pe32_plus: bool,
    pub number_of_sections: usize,
    pub section_table: usize,
    pub section_alignment: u32,
    pub size_of_image: u32,
}

impl PeView {
    pub fn parse(buf: &[u8]) -> Option<PeView> {
        if buf.get(..2)? != DOS_MAGIC {
            return None;
        }
        let e_lfanew = read_u32(buf, DOS_E_LFANEW_OFFSET)? as usize;
        if buf.get(e_lfanew..e_lfanew + 4)? != PE_SIGNATURE {
            return None;
        }
        let file_header = e_lfanew + 4;
        let opt = file_header + FILE_HEADER_SIZE;
        let is_pe32_plus = match read_u16(buf, opt + OPT_MAGIC_OFFSET)? {
            OPT_MAGIC_PE32PLUS => true,
            OPT_MAGIC_PE32 => false,
            _ => return None,
        };
        let size_of_optional = read_u16(buf, file_header + FILE_SIZE_OF_OPTIONAL_HEADER_OFFSET)?;
        Some(PeView {
            opt,
            file_header,
            is_pe32_plus,
            number_of_sections: read_u16(buf, file_header + FILE_NUMBER_OF_SECTIONS_OFFSET)?
                as usize,
            section_table: opt + size_of_optional as usize,
            section_alignment: read_u32(buf, opt + OPT_SECTION_ALIGNMENT_OFFSET)?,
            size_of_image: read_u32(buf, opt + OPT_SIZE_OF_IMAGE_OFFSET)?,
        })
    }

    pub fn section_header(&self, index: usize) -> usize {
        self.section_table + index * SECTION_HEADER_SIZE
    }
}
