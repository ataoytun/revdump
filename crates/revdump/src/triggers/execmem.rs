use std::collections::HashSet;

/// A region whose execute permission we stripped (DEP-flip) so its first execution faults. The
/// fault address is the OEP.
pub struct WatchedRegion {
    pub base: usize,
    pub size: usize,
    /// The executable protection the packer asked for, restored once we catch the fault.
    pub original_protect: u32,
}

/// Shared view of the executable memory a packer is preparing: regions we DEP-flipped, plus the
/// TLS callbacks (which run before the entry point and must not be mistaken for the OEP). The
/// alloc-watch records regions here; the OEP catch consults it.
#[derive(Default)]
pub struct ExecMem {
    watched: Vec<WatchedRegion>,
    tls_callbacks: HashSet<usize>,
}

impl ExecMem {
    pub fn record_tls(&mut self, callbacks: &[usize]) {
        self.tls_callbacks.extend(callbacks.iter().copied());
    }

    pub fn is_tls_callback(&self, addr: usize) -> bool {
        self.tls_callbacks.contains(&addr)
    }

    pub fn watch(&mut self, base: usize, size: usize, original_protect: u32) {
        self.watched.push(WatchedRegion {
            base,
            size,
            original_protect,
        });
    }

    /// The watched region containing `addr` (the faulting OEP), if any.
    pub fn region_of(&self, addr: usize) -> Option<&WatchedRegion> {
        self.watched
            .iter()
            .find(|r| addr >= r.base && addr < r.base.saturating_add(r.size))
    }
}
