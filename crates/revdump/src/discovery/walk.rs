use core::ffi::c_void;
use core::mem::{size_of, MaybeUninit};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
};
use windows_sys::Win32::System::ProcessStatus::GetMappedFileNameW;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// MEM_IMAGE: backed by a mapped image (SEC_IMAGE) section.
    Image,
    /// MEM_MAPPED: backed by a data file/section.
    Mapped,
    /// MEM_PRIVATE: heap/VirtualAlloc memory; where reflective loads and shellcode live.
    Private,
}

#[derive(Debug, Clone)]
pub struct Region {
    pub base: usize,
    pub alloc_base: usize,
    pub size: usize,
    pub protect: u32,
    pub kind: RegionKind,
    /// Device path of the backing file for Image/Mapped regions (e.g. \Device\HarddiskVolumeN\...).
    pub mapped_path: Option<String>,
}

const EXECUTABLE: u32 =
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

impl Region {
    pub fn is_executable(&self) -> bool {
        self.protect & EXECUTABLE != 0
    }
}

/// Walk the committed address space via VirtualQueryEx, classifying every region. Stops when the
/// query falls off the end of user space (returns 0) or the cursor would wrap.
pub fn enumerate_regions(process: HANDLE) -> Vec<Region> {
    let mut regions = Vec::new();
    let mut addr: usize = 0;
    loop {
        let mut mbi = MaybeUninit::<MEMORY_BASIC_INFORMATION>::zeroed();
        // SAFETY: VirtualQueryEx fills `mbi`; a zero return means there's nothing mapped at/after
        // `addr`, i.e. we've reached the end of the address space.
        let written = unsafe {
            VirtualQueryEx(
                process,
                addr as *const c_void,
                mbi.as_mut_ptr(),
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            break;
        }
        // SAFETY: a non-zero return means the structure was populated.
        let mbi = unsafe { mbi.assume_init() };
        let size = mbi.RegionSize;
        if size == 0 {
            break;
        }
        let base = mbi.BaseAddress as usize;

        if mbi.State == MEM_COMMIT {
            let kind = match mbi.Type {
                MEM_IMAGE => RegionKind::Image,
                MEM_MAPPED => RegionKind::Mapped,
                _ => RegionKind::Private,
            };
            let mapped_path = match kind {
                RegionKind::Image | RegionKind::Mapped => mapped_file_name(process, base),
                RegionKind::Private => None,
            };
            regions.push(Region {
                base,
                alloc_base: mbi.AllocationBase as usize,
                size,
                protect: mbi.Protect,
                kind,
                mapped_path,
            });
        }

        match base.checked_add(size) {
            Some(next) if next > addr => addr = next,
            _ => break,
        }
    }
    regions
}

fn mapped_file_name(process: HANDLE, addr: usize) -> Option<String> {
    let mut buf = [0u16; 1024];
    // SAFETY: GetMappedFileNameW writes at most buf.len() wchars and returns the count (0 = none).
    let len = unsafe {
        GetMappedFileNameW(
            process,
            addr as *const c_void,
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}
