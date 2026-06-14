use crate::error::{Result, RevError};
use crate::reconstruct::pe::{self, PeView};

/// Rewrite the section table so the on-disk layout mirrors memory (RVA == file offset).
///
/// This is the default dump mode: FileAlignment becomes SectionAlignment and each section's raw
/// pointer/size become its virtual address/size, so the dumped file is byte-for-byte the
/// in-memory image and IDA/Ghidra map it without re-shuffling raw vs. virtual slack — the layout
/// a packer already produced in memory is exactly what we want to analyze.
pub fn memory_align(image: &mut [u8]) -> Result<()> {
    let view = PeView::parse(image)
        .ok_or_else(|| RevError::Reconstruct("image has no usable PE header".into()))?;
    let align = view.section_alignment;
    if align == 0 {
        return Err(RevError::Reconstruct("section alignment is zero".into()));
    }

    pe::write_u32(image, view.opt + pe::OPT_FILE_ALIGNMENT_OFFSET, align);
    // Headers occupy the first SectionAlignment bytes; sections begin at >= SectionAlignment.
    pe::write_u32(image, view.opt + pe::OPT_SIZE_OF_HEADERS_OFFSET, align);

    for i in 0..view.number_of_sections {
        let sh = view.section_header(i);
        let vaddr = pe::read_u32(image, sh + pe::SEC_VIRTUAL_ADDRESS_OFFSET)
            .ok_or_else(|| RevError::Reconstruct("truncated section table".into()))?;
        let vsize = pe::read_u32(image, sh + pe::SEC_VIRTUAL_SIZE_OFFSET)
            .ok_or_else(|| RevError::Reconstruct("truncated section table".into()))?;
        // Cap raw size to the image we actually captured so no section claims bytes past its end.
        let raw = pe::round_up(vsize, align).min(view.size_of_image.saturating_sub(vaddr));
        pe::write_u32(image, sh + pe::SEC_POINTER_TO_RAW_DATA_OFFSET, vaddr);
        pe::write_u32(image, sh + pe::SEC_SIZE_OF_RAW_DATA_OFFSET, raw);
    }
    Ok(())
}
