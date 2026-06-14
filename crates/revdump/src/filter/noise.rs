use crate::reconstruct::exports::ExportCatalog;
use crate::reconstruct::pe;

// Real code references the outside world; require a couple of resolvable pointers before treating
// a loose chunk as worth dumping. Lowering this would surface more (noisier) candidates.
const MIN_IMPORT_REFS: usize = 2;

/// Heuristic guard against false-positive code chunks: a region is "plausible code" if at least a
/// couple of pointer-sized, pointer-aligned values resolve to real exports. Pure data and
/// zero-filled pages almost never do. (Catches absolute IAT-style references; code that reaches
/// imports only via RIP-relative thunks won't trip it, a deliberately conservative knob.)
pub fn is_plausible_code(bytes: &[u8], catalog: &ExportCatalog, ptr: usize) -> bool {
    let mut refs = 0;
    let mut off = 0;
    while off + ptr <= bytes.len() {
        let value = if ptr == 8 {
            pe::read_u64(bytes, off)
        } else {
            pe::read_u32(bytes, off).map(u64::from)
        };
        if value.and_then(|v| catalog.resolve(v)).is_some() {
            refs += 1;
            if refs >= MIN_IMPORT_REFS {
                return true;
            }
        }
        off += ptr;
    }
    false
}
