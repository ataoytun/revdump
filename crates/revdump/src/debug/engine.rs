use core::ffi::c_void;
use core::mem::MaybeUninit;
use std::collections::HashMap;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    ReadProcessMemory, WaitForDebugEvent, WriteProcessMemory, DEBUG_EVENT,
};

use crate::debug::context;
use crate::error::{Result, RevError};

const EXCEPTION_DEBUG_EVENT: u32 = 1;
const CREATE_PROCESS_DEBUG_EVENT: u32 = 3;
const EXIT_PROCESS_DEBUG_EVENT: u32 = 5;
const STATUS_BREAKPOINT: i32 = 0x8000_0003u32 as i32;
const DBG_CONTINUE: i32 = 0x0001_0002;
const DBG_EXCEPTION_NOT_HANDLED: i32 = 0x8001_0001u32 as i32;
const INFINITE: u32 = 0xFFFF_FFFF;
const BREAKPOINT_BYTE: u8 = 0xCC;

/// What [`Debugger::cont`] stopped on. Uninteresting events (DLL loads, thread create/exit, other
/// exceptions) are handled internally and never surface here.
pub enum Stop {
    /// The system's initial breakpoint — fired after the loader mapped the image + dependencies
    /// but before TLS callbacks / the entry point. The place to arm breakpoints and, at M7, apply
    /// anti-debug patches.
    InitialBreak,
    Breakpoint(usize),
    Exited(u32),
}

/// External Win32 debugger. No code is injected into the target — control is entirely through the
/// debug event loop plus software breakpoints (0xCC) and memory writes.
pub struct Debugger {
    pid: u32,
    process: HANDLE,
    breakpoints: HashMap<usize, u8>,
    // The last reported event, continued at the start of the next cont()/detach().
    pending: Option<(u32, u32, i32)>,
    initial_seen: bool,
}

impl Debugger {
    pub fn attach(pid: u32) -> Result<Debugger> {
        // SAFETY: documented debug API; a zero return means failure.
        if unsafe { DebugActiveProcess(pid) } == 0 {
            return Err(RevError::Access(format!(
                "DebugActiveProcess({pid}) failed"
            )));
        }
        // Keep the target alive when we detach.
        unsafe { DebugSetProcessKillOnExit(0) };
        Ok(Debugger {
            pid,
            process: core::ptr::null_mut(),
            breakpoints: HashMap::new(),
            pending: None,
            initial_seen: false,
        })
    }

    pub fn process(&self) -> HANDLE {
        self.process
    }

    /// Continue the target and return at the next interesting stop.
    pub fn cont(&mut self) -> Result<Stop> {
        self.continue_pending()?;
        loop {
            let event = self.wait()?;
            let (pid, tid) = (event.dwProcessId, event.dwThreadId);
            self.pending = Some((pid, tid, DBG_CONTINUE));

            match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    // SAFETY: union is the CreateProcessInfo variant for this event code.
                    let info = unsafe { event.u.CreateProcessInfo };
                    self.process = info.hProcess;
                    if !info.hFile.is_null() {
                        unsafe { CloseHandle(info.hFile) };
                    }
                    self.continue_pending()?;
                }
                EXCEPTION_DEBUG_EVENT => {
                    // SAFETY: union is the Exception variant for this event code.
                    let record = unsafe { event.u.Exception.ExceptionRecord };
                    let addr = record.ExceptionAddress as usize;
                    if record.ExceptionCode == STATUS_BREAKPOINT {
                        if !self.initial_seen {
                            self.initial_seen = true;
                            return Ok(Stop::InitialBreak);
                        }
                        if let Some(orig) = self.breakpoints.get(&addr).copied() {
                            self.write_byte(addr, orig)?;
                            context::set_instruction_pointer(tid, addr)?;
                            self.breakpoints.remove(&addr);
                            return Ok(Stop::Breakpoint(addr));
                        }
                    }
                    // Not ours: hand the exception back to the application.
                    self.pending = Some((pid, tid, DBG_EXCEPTION_NOT_HANDLED));
                    self.continue_pending()?;
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    // SAFETY: union is the ExitProcess variant for this event code.
                    let code = unsafe { event.u.ExitProcess.dwExitCode };
                    self.pending = None;
                    return Ok(Stop::Exited(code));
                }
                _ => self.continue_pending()?,
            }
        }
    }

    pub fn set_breakpoint(&mut self, addr: usize) -> Result<()> {
        let mut original = [0u8; 1];
        let mut read = 0usize;
        // SAFETY: read the original byte at the breakpoint site.
        let ok = unsafe {
            ReadProcessMemory(
                self.process,
                addr as *const c_void,
                original.as_mut_ptr().cast(),
                1,
                &mut read,
            )
        };
        if ok == 0 || read != 1 {
            return Err(RevError::Access(format!(
                "cannot read breakpoint site {addr:#x}"
            )));
        }
        self.write_byte(addr, BREAKPOINT_BYTE)?;
        self.breakpoints.insert(addr, original[0]);
        Ok(())
    }

    fn write_byte(&self, addr: usize, value: u8) -> Result<()> {
        let buf = [value];
        let mut written = 0usize;
        // SAFETY: write a single byte into the target's address space.
        let ok = unsafe {
            WriteProcessMemory(
                self.process,
                addr as *mut c_void,
                buf.as_ptr().cast(),
                1,
                &mut written,
            )
        };
        if ok == 0 || written != 1 {
            return Err(RevError::Access(format!(
                "cannot write breakpoint byte at {addr:#x}"
            )));
        }
        Ok(())
    }

    fn wait(&self) -> Result<DEBUG_EVENT> {
        let mut event = MaybeUninit::<DEBUG_EVENT>::zeroed();
        // SAFETY: WaitForDebugEvent fills the event; INFINITE blocks until one arrives.
        if unsafe { WaitForDebugEvent(event.as_mut_ptr(), INFINITE) } == 0 {
            return Err(RevError::Access("WaitForDebugEvent failed".into()));
        }
        Ok(unsafe { event.assume_init() })
    }

    fn continue_pending(&mut self) -> Result<()> {
        if let Some((pid, tid, status)) = self.pending.take() {
            // SAFETY: continues the last reported debug event.
            if unsafe { ContinueDebugEvent(pid, tid, status) } == 0 {
                return Err(RevError::Access("ContinueDebugEvent failed".into()));
            }
        }
        Ok(())
    }

    pub fn detach(mut self) -> Result<()> {
        self.continue_pending()?;
        // Remove any breakpoints we didn't consume so the target isn't left with 0xCC bytes.
        for (addr, original) in std::mem::take(&mut self.breakpoints) {
            let _ = self.write_byte(addr, original);
        }
        // SAFETY: stop debugging; KillOnExit was disabled, so the target keeps running.
        unsafe { DebugActiveProcessStop(self.pid) };
        Ok(())
    }
}
