use windows_sys::Win32::System::ProcessStatus::EnumProcesses;

/// Snapshot of every process id, for the full-system sweep.
pub fn enumerate_pids() -> Vec<u32> {
    let mut pids = vec![0u32; 8192];
    let mut needed = 0u32;
    let capacity = (pids.len() * core::mem::size_of::<u32>()) as u32;
    // SAFETY: EnumProcesses writes up to `capacity` bytes and reports the used count in `needed`.
    let ok = unsafe { EnumProcesses(pids.as_mut_ptr(), capacity, &mut needed) };
    if ok == 0 {
        return Vec::new();
    }
    pids.truncate(needed as usize / core::mem::size_of::<u32>());
    pids.retain(|&pid| pid != 0);
    pids
}
