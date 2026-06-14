//! Hand-rolled NTAPI surface. Everything undocumented lives here so the rest of the crate stays
//! free of raw layout assumptions. The struct layouts are asserted at compile time (below): a
//! wrong offset for any field we actually read fails the build rather than silently misreading a
//! packer's process memory.

#![allow(non_snake_case)]

use core::ffi::c_void;
use core::mem::{offset_of, size_of};

use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

// Partial PEB: only the prefix through NtGlobalFlag is modeled. The tail padding differs per
// architecture; the asserts pin the fields we read (BeingDebugged, ImageBaseAddress, Ldr,
// NtGlobalFlag) to their documented offsets.
#[cfg(target_pointer_width = "64")]
const PEB_PAD_AFTER_LDR: usize = 0xBC - 0x18 - 8;
#[cfg(target_pointer_width = "32")]
const PEB_PAD_AFTER_LDR: usize = 0x68 - 0x0C - 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Peb {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub bit_field: u8,
    // On x64 the pointer at Mutant is 8-aligned, so 4 bytes of padding sit here; on x86 Mutant
    // follows immediately.
    #[cfg(target_pointer_width = "64")]
    _pad_mutant: [u8; 4],
    pub mutant: *mut c_void,
    pub image_base_address: *mut c_void,
    pub ldr: *mut PebLdrData,
    _pad_after_ldr: [u8; PEB_PAD_AFTER_LDR],
    pub nt_global_flag: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PebLdrData {
    pub length: u32,
    pub initialized: u8,
    pub ss_handle: *mut c_void,
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LdrDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: *mut c_void,
    pub entry_point: *mut c_void,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessBasicInformation {
    pub exit_status: NTSTATUS,
    pub peb_base_address: *mut Peb,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
}

// PS_PROTECTION (a single byte): Type:3, Audit:1, Signer:4. Used to recognize PP/PPL targets.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PsProtection(pub u8);

impl PsProtection {
    pub fn protection_type(self) -> u8 {
        self.0 & 0x07
    }
    pub fn signer(self) -> u8 {
        (self.0 >> 4) & 0x0F
    }
    pub fn is_protected(self) -> bool {
        self.protection_type() != 0
    }
}

// ProcessInformationClass values we touch.
pub const PROCESS_BASIC_INFORMATION_CLASS: i32 = 0;
// ProcessWow64Information: yields the target's PEB32 address (nonzero) for a 32-bit WOW64 process,
// 0 for a native process. That's how we tell a target's bitness from our own.
pub const PROCESS_WOW64_INFORMATION: i32 = 26;
pub const PROCESS_PROTECTION_INFORMATION: i32 = 61;

pub const STATUS_PARTIAL_COPY: NTSTATUS = 0x8000_000Du32 as i32;

pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

#[link(name = "ntdll")]
extern "system" {
    pub fn NtReadVirtualMemory(
        process: HANDLE,
        base: *const c_void,
        buffer: *mut c_void,
        size: usize,
        bytes_read: *mut usize,
    ) -> NTSTATUS;

    pub fn NtWriteVirtualMemory(
        process: HANDLE,
        base: *mut c_void,
        buffer: *const c_void,
        size: usize,
        bytes_written: *mut usize,
    ) -> NTSTATUS;

    pub fn NtQueryInformationProcess(
        process: HANDLE,
        class: i32,
        info: *mut c_void,
        len: u32,
        return_len: *mut u32,
    ) -> NTSTATUS;
}

// A wrong layout fails the build here, before it can ever misread target memory.
const _: () = {
    assert!(offset_of!(Peb, being_debugged) == 0x02);
    assert!(offset_of!(ProcessBasicInformation, exit_status) == 0x00);

    #[cfg(target_pointer_width = "64")]
    {
        assert!(offset_of!(Peb, image_base_address) == 0x10);
        assert!(offset_of!(Peb, ldr) == 0x18);
        assert!(offset_of!(Peb, nt_global_flag) == 0xBC);
        assert!(offset_of!(PebLdrData, in_load_order_module_list) == 0x10);
        assert!(offset_of!(LdrDataTableEntry, dll_base) == 0x30);
        assert!(offset_of!(LdrDataTableEntry, size_of_image) == 0x40);
        assert!(offset_of!(LdrDataTableEntry, full_dll_name) == 0x48);
        assert!(offset_of!(LdrDataTableEntry, base_dll_name) == 0x58);
        assert!(offset_of!(ProcessBasicInformation, peb_base_address) == 0x08);
        assert!(size_of::<UnicodeString>() == 16);
    }
    #[cfg(target_pointer_width = "32")]
    {
        assert!(offset_of!(Peb, image_base_address) == 0x08);
        assert!(offset_of!(Peb, ldr) == 0x0C);
        assert!(offset_of!(Peb, nt_global_flag) == 0x68);
        assert!(offset_of!(PebLdrData, in_load_order_module_list) == 0x0C);
        assert!(offset_of!(LdrDataTableEntry, dll_base) == 0x18);
        assert!(offset_of!(LdrDataTableEntry, size_of_image) == 0x20);
        assert!(offset_of!(LdrDataTableEntry, full_dll_name) == 0x24);
        assert!(offset_of!(LdrDataTableEntry, base_dll_name) == 0x2C);
        assert!(offset_of!(ProcessBasicInformation, peb_base_address) == 0x04);
        assert!(size_of::<UnicodeString>() == 8);
    }
};
