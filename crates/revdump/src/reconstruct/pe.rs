//! PE format constants and small header readers — the single source of truth for offsets/flags
//! shared across discovery and reconstruction. Grown per-milestone; nothing here duplicates an
//! offset defined elsewhere.

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
// ImageBase is a 4-byte field at 0x1C on PE32, an 8-byte field at 0x18 on PE32+.
pub const OPT_IMAGE_BASE_OFFSET_PE32: usize = 0x1C;
pub const OPT_IMAGE_BASE_OFFSET_PE32PLUS: usize = 0x18;

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
