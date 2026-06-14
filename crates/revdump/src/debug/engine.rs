use core::ffi::c_void;
use core::mem::MaybeUninit;
use std::collections::{HashMap, HashSet};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    ReadProcessMemory, WaitForDebugEvent, WriteProcessMemory, DEBUG_EVENT,
};
use windows_sys::Win32::System::Memory::VirtualProtectEx;

use crate::debug::context;
use crate::error::{Result, RevError};

const EXCEPTION_DEBUG_EVENT: u32 = 1;
const CREATE_PROCESS_DEBUG_EVENT: u32 = 3;
const EXIT_PROCESS_DEBUG_EVENT: u32 = 5;
const STATUS_BREAKPOINT: i32 = 0x8000_0003u32 as i32;
const STATUS_SINGLE_STEP: i32 = 0x8000_0004u32 as i32;
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
    /// A non-breakpoint exception (access violation, guard violation, ...). Surfaced so the OEP
    /// finder can recognize the execution fault it induced; defaults to "not handled" (passed to
    /// the app) unless the caller calls [`Debugger::mark_handled`].
    Exception {
        code: i32,
        address: usize,
    },
    Exited(u32),
}

/// External Win32 debugger. No code is injected into the target — control is entirely through the
/// debug event loop plus software breakpoints (0xCC) and memory writes.
pub struct Debugger {
    pid: u32,
    process: HANDLE,
    breakpoints: HashMap<usize, u8>,
    // Breakpoints that re-arm after firing (vs. one-shot), via a single-step over the original
    // instruction. `rearm` holds the (address, thread) of the step in progress.
    persistent: HashSet<usize>,
    rearm: Option<(usize, u32)>,
    // The last reported event, continued at the start of the next cont()/detach().
    pending: Option<(u32, u32, i32)>,
    initial_seen: bool,
    last_thread: u32,
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
            persistent: HashSet::new(),
            rearm: None,
            pending: None,
            initial_seen: false,
            last_thread: 0,
        })
    }

    pub fn process(&self) -> HANDLE {
        self.process
    }

    /// Thread id of the most recent stop — needed to read/modify its registers.
    pub fn current_thread(&self) -> u32 {
        self.last_thread
    }

    /// Mark the surfaced exception as handled, so the faulting instruction re-executes on the next
    /// `cont()` instead of being passed to the application.
    pub fn mark_handled(&mut self) {
        if let Some(p) = self.pending.as_mut() {
            p.2 = DBG_CONTINUE;
        }
    }

    /// Change a region's protection in the target (VirtualProtectEx), e.g. to restore execute at
    /// the OEP after catching the DEP fault.
    pub fn protect(&self, base: usize, size: usize, new_protect: u32) -> Result<()> {
        let mut old = 0u32;
        // SAFETY: VirtualProtectEx on a committed region of the target.
        let ok = unsafe {
            VirtualProtectEx(
                self.process,
                base as *mut core::ffi::c_void,
                size,
                new_protect,
                &mut old,
            )
        };
        if ok == 0 {
            return Err(RevError::Access(format!(
                "VirtualProtectEx({base:#x}) failed"
            )));
        }
        Ok(())
    }

    /// Continue the target and return at the next interesting stop.
    pub fn cont(&mut self) -> Result<Stop> {
        // If a persistent breakpoint just fired, single-step its original instruction so we can
        // re-arm it on the resulting STATUS_SINGLE_STEP.
        if let Some((_, tid)) = self.rearm {
            context::set_trap_flag(tid, true)?;
        }
        self.continue_pending()?;
        loop {
            let event = self.wait()?;
            let (pid, tid) = (event.dwProcessId, event.dwThreadId);
            self.pending = Some((pid, tid, DBG_CONTINUE));
            self.last_thread = tid;

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
                    let code = record.ExceptionCode;
                    if code == STATUS_SINGLE_STEP {
                        // We stepped over a persistent breakpoint's original instruction: re-arm
                        // it and clear the trap flag.
                        if let Some((bp, bp_tid)) = self.rearm.take() {
                            self.write_byte(bp, BREAKPOINT_BYTE)?;
                            context::set_trap_flag(bp_tid, false)?;
                        } else {
                            self.pending = Some((pid, tid, DBG_EXCEPTION_NOT_HANDLED));
                        }
                        self.continue_pending()?;
                    } else if code == STATUS_BREAKPOINT {
                        if !self.initial_seen {
                            self.initial_seen = true;
                            return Ok(Stop::InitialBreak);
                        }
                        if let Some(orig) = self.breakpoints.get(&addr).copied() {
                            self.write_byte(addr, orig)?;
                            context::set_instruction_pointer(tid, addr)?;
                            if self.persistent.contains(&addr) {
                                // Keep the entry; step over the original instruction, then re-arm.
                                self.rearm = Some((addr, tid));
                            } else {
                                self.breakpoints.remove(&addr);
                            }
                            return Ok(Stop::Breakpoint(addr));
                        }
                        // An unknown breakpoint: hand it back to the application.
                        self.pending = Some((pid, tid, DBG_EXCEPTION_NOT_HANDLED));
                        self.continue_pending()?;
                    } else {
                        // Any other exception (access/guard violation, ...) goes to the caller,
                        // defaulting to "not handled" so it reaches the app unless handled.
                        self.pending = Some((pid, tid, DBG_EXCEPTION_NOT_HANDLED));
                        return Ok(Stop::Exception {
                            code,
                            address: addr,
                        });
                    }
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

    /// Like [`set_breakpoint`](Self::set_breakpoint) but re-arms after each hit (for functions
    /// called repeatedly, e.g. NtProtectVirtualMemory).
    pub fn set_persistent_breakpoint(&mut self, addr: usize) -> Result<()> {
        self.set_breakpoint(addr)?;
        self.persistent.insert(addr);
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
