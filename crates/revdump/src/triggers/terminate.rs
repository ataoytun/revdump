use windows_sys::Win32::Foundation::HANDLE;

use crate::debug::engine::{Debugger, Stop};
use crate::debug::symbols::ntdll_export;
use crate::error::{Result, RevError};

// Every exit path (ExitProcess, return-from-main, CLR shutdown, ...) funnels through the
// NtTerminateProcess syscall as its final step, so breakpointing it catches the process at the
// last moment its memory is fully intact — ideal for short-lived stages.
const EXIT_FUNCTION: &str = "NtTerminateProcess";

/// Attach to `pid`, breakpoint the exit path, and invoke `on_exit` with the target handle when the
/// process is about to terminate — then let it proceed to exit. Returns whether the exit was
/// caught (false if the process exited before we armed, or by a path we don't watch).
pub fn monitor(pid: u32, mut on_exit: impl FnMut(HANDLE) -> Result<()>) -> Result<bool> {
    let exit_addr = ntdll_export(EXIT_FUNCTION)
        .ok_or_else(|| RevError::Access(format!("could not resolve ntdll!{EXIT_FUNCTION}")))?;

    let mut dbg = Debugger::attach(pid)?;
    let mut caught = false;
    loop {
        match dbg.cont()? {
            Stop::InitialBreak => dbg.set_breakpoint(exit_addr)?,
            Stop::Breakpoint(_) => {
                on_exit(dbg.process())?;
                caught = true;
                break;
            }
            Stop::Exited(_) => break,
        }
    }
    // detach() restores the breakpoint byte and stops debugging, so the target runs on and exits.
    dbg.detach()?;
    Ok(caught)
}
