use crate::reconstruct::pe;

// Native arch only: revdump64 synthesizes PE32+, revdump32 synthesizes PE32. Each binary dumps
// its own architecture, so there is no cross-bitness case here. cfg!() (not #[cfg]) keeps both
// arches' constants referenced, so neither reads as dead code on a single-arch build.
const NATIVE_PE32_PLUS: bool = cfg!(target_pointer_width = "64");
const OPT_MAGIC: u16 = if NATIVE_PE32_PLUS {
    pe::OPT_MAGIC_PE32PLUS
} else {
    pe::OPT_MAGIC_PE32
};
const OPT_HEADER_SIZE: u16 = if NATIVE_PE32_PLUS { 0xF0 } else { 0xE0 };
const MACHINE: u16 = pe::machine_for(NATIVE_PE32_PLUS);
const CHARACTERISTICS: u16 = pe::FILE_EXECUTABLE_IMAGE
    | if NATIVE_PE32_PLUS {
        pe::FILE_LARGE_ADDRESS_AWARE
    } else {
        0
    };

const HEADER_PAGE: u32 = 0x1000;
const ALIGN: u32 = 0x1000;
// goblin (and some loaders) require e_lfanew strictly past the 0x40-byte DOS header; leave a stub.
const E_LFANEW: u32 = 0x80;

/// Build a minimal single-section PE around a headerless executable region so it loads for
/// analysis. The synthesized header occupies the first page and the code follows at RVA 0x1000;
/// ImageBase is `base - 0x1000` so the code's load address equals its original `base` and an
/// analyst sees the real addresses. Used both for loose chunks and for packer-erased headers
/// (where we treat the whole region as one code section).
pub fn synthesize_pe(base: usize, code: &[u8]) -> Vec<u8> {
    let code_size = code.len() as u32;
    let raw = pe::round_up(code_size, ALIGN);
    let size_of_image = HEADER_PAGE + raw;
    let image_base = (base as u64).saturating_sub(HEADER_PAGE as u64);

    let mut w = Writer::default();
    w.bytes(&pe::DOS_MAGIC);
    w.pad_to(pe::DOS_E_LFANEW_OFFSET);
    w.u32(E_LFANEW);
    w.pad_to(E_LFANEW as usize);
    w.bytes(&pe::PE_SIGNATURE);

    // IMAGE_FILE_HEADER
    w.u16(MACHINE);
    w.u16(1); // NumberOfSections
    w.u32(0); // TimeDateStamp
    w.u32(0); // PointerToSymbolTable
    w.u32(0); // NumberOfSymbols
    w.u16(OPT_HEADER_SIZE);
    w.u16(CHARACTERISTICS);

    // IMAGE_OPTIONAL_HEADER
    w.u16(OPT_MAGIC);
    w.u16(0); // linker major/minor
    w.u32(raw); // SizeOfCode
    w.u32(0); // SizeOfInitializedData
    w.u32(0); // SizeOfUninitializedData
    w.u32(HEADER_PAGE); // AddressOfEntryPoint (start of code)
    w.u32(HEADER_PAGE); // BaseOfCode
    #[cfg(target_pointer_width = "32")]
    {
        w.u32(HEADER_PAGE); // BaseOfData (PE32 only)
        w.u32(image_base as u32);
    }
    #[cfg(target_pointer_width = "64")]
    {
        w.u64(image_base);
    }
    w.u32(ALIGN); // SectionAlignment
    w.u32(ALIGN); // FileAlignment
    w.u16(6); // MajorOperatingSystemVersion
    w.u16(0);
    w.u16(0); // image version
    w.u16(0);
    w.u16(6); // MajorSubsystemVersion
    w.u16(0);
    w.u32(0); // Win32VersionValue
    w.u32(size_of_image);
    w.u32(HEADER_PAGE); // SizeOfHeaders
    w.u32(0); // CheckSum
    w.u16(pe::SUBSYSTEM_WINDOWS_CUI);
    w.u16(0); // DllCharacteristics
    #[cfg(target_pointer_width = "64")]
    {
        w.u64(0x10_0000); // StackReserve
        w.u64(0x1000); // StackCommit
        w.u64(0x10_0000); // HeapReserve
        w.u64(0x1000); // HeapCommit
    }
    #[cfg(target_pointer_width = "32")]
    {
        w.u32(0x10_0000);
        w.u32(0x1000);
        w.u32(0x10_0000);
        w.u32(0x1000);
    }
    w.u32(0); // LoaderFlags
    w.u32(16); // NumberOfRvaAndSizes
    for _ in 0..16 {
        w.u32(0); // directory RVA
        w.u32(0); // directory size
    }

    // IMAGE_SECTION_HEADER
    w.bytes(b".text\0\0\0");
    w.u32(code_size); // VirtualSize
    w.u32(HEADER_PAGE); // VirtualAddress
    w.u32(raw); // SizeOfRawData
    w.u32(HEADER_PAGE); // PointerToRawData
    w.u32(0); // PointerToRelocations
    w.u32(0); // PointerToLinenumbers
    w.u16(0); // NumberOfRelocations
    w.u16(0); // NumberOfLinenumbers
              // RX for recovered code (not blanket RWX) to cut PE-viewer/AV noise.
    w.u32(pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ);

    w.pad_to(HEADER_PAGE as usize);
    w.bytes(code);
    w.pad_to((HEADER_PAGE + raw) as usize);
    w.buf
}

#[derive(Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    #[cfg(target_pointer_width = "64")]
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    fn pad_to(&mut self, off: usize) {
        if self.buf.len() < off {
            self.buf.resize(off, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goblin::pe::PE;

    #[test]
    fn synthesized_pe_is_valid() {
        let base = 0x0040_0000usize;
        let code = vec![0x90u8; 0x180]; // NOP sled
        let bytes = synthesize_pe(base, &code);

        let pe = PE::parse(&bytes).expect("synthesized PE must parse");
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name().unwrap(), ".text");
        let opt = pe.header.optional_header.expect("optional header");
        assert_eq!(opt.windows_fields.image_base, (base - 0x1000) as u64);
        assert_eq!(opt.standard_fields.address_of_entry_point, 0x1000);
        // Code lands at RVA 0x1000 -> original base.
        assert_eq!(opt.windows_fields.image_base + 0x1000, base as u64);
    }
}
