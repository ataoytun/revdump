use windows_sys::Win32::Foundation::HANDLE;

use crate::error::Result;
use crate::nt;

pub const PAGE_SIZE: usize = 0x1000;

pub trait MemoryReader {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<usize>;
}

/// Reads target memory through a process handle. The caller owns the handle's lifetime — both a
/// freshly-opened [`OwnedProcess`](crate::access::open::OwnedProcess) handle and a debug-event
/// handle outlive the reads done with them.
pub struct ProcessReader {
    handle: HANDLE,
}

impl ProcessReader {
    pub fn new(handle: HANDLE) -> Self {
        Self { handle }
    }
}

impl MemoryReader for ProcessReader {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<usize> {
        nt::read_memory(self.handle, addr, buf)
    }
}

/// A byte range `[start, start+len)` that could not be read.
pub type Gap = (usize, usize);

/// Read `len` bytes from `base`, never aborting on a guarded/unreadable page. Pages that fail are
/// zero-filled and recorded in the returned gap list, so one bad page costs only itself.
pub fn read_best_effort<R: MemoryReader>(
    reader: &R,
    base: usize,
    len: usize,
) -> (Vec<u8>, Vec<Gap>) {
    let mut out = vec![0u8; len];
    let mut gaps = Vec::new();

    // Fast path: most regions read whole in one call.
    if let Ok(n) = reader.read(base, &mut out) {
        if n == len {
            return (out, gaps);
        }
    }

    // Slow path: page-granular, so a single guarded page doesn't sink the region.
    let mut off = 0;
    while off < len {
        let chunk = PAGE_SIZE.min(len - off);
        let slice = &mut out[off..off + chunk];
        let ok = matches!(reader.read(base + off, slice), Ok(n) if n == chunk);
        if !ok {
            slice.fill(0);
            gaps.push((base + off, chunk));
        }
        off += chunk;
    }
    (out, gaps)
}
