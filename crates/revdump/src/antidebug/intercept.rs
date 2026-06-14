use std::collections::HashMap;

use crate::debug::context;
use crate::debug::engine::Debugger;
use crate::debug::symbols::ntdll_export;
use crate::error::{Result, RevError};
use crate::nt;

// ProcessInformationClass / ThreadInformationClass values packers use to detect a debugger.
const PROCESS_DEBUG_PORT: i32 = 7;
const PROCESS_DEBUG_OBJECT_HANDLE: i32 = 30;
const PROCESS_DEBUG_FLAGS: i32 = 31;
const THREAD_HIDE_FROM_DEBUGGER: i32 = 17;

const STATUS_PORT_NOT_SET: usize = 0xC000_0353;
// A non-existent ThreadInformationClass: NtSetInformationThread then returns an error and the hide
// never takes effect (callers ignore the return value).
const INVALID_INFO_CLASS: usize = 0xFFFF_FFFF;

const PTR: usize = core::mem::size_of::<usize>();

/// Rewrites the results of the NTAPI calls packers use to detect a debugger, so a debugged target
/// sees the values it would see running normally. Driven entirely by breakpoints — no injection.
pub struct Interceptor {
    query_info: usize,
    set_thread: usize,
    // Return-site breakpoints awaiting a NtQueryInformationProcess output rewrite.
    pending: HashMap<usize, (i32, usize)>,
}

impl Interceptor {
    pub fn arm(dbg: &mut Debugger) -> Result<Interceptor> {
        let query_info = ntdll_export("NtQueryInformationProcess").ok_or_else(|| {
            RevError::Access("could not resolve NtQueryInformationProcess".into())
        })?;
        let set_thread = ntdll_export("NtSetInformationThread")
            .ok_or_else(|| RevError::Access("could not resolve NtSetInformationThread".into()))?;
        dbg.set_persistent_breakpoint(query_info)?;
        dbg.set_persistent_breakpoint(set_thread)?;
        Ok(Interceptor {
            query_info,
            set_thread,
            pending: HashMap::new(),
        })
    }

    /// Handle `addr` if it's one of ours; returns whether it was consumed.
    pub fn on_breakpoint(&mut self, dbg: &mut Debugger, addr: usize) -> Result<bool> {
        if addr == self.query_info {
            self.on_query_entry(dbg)?;
            Ok(true)
        } else if addr == self.set_thread {
            self.on_set_thread(dbg)?;
            Ok(true)
        } else if let Some((class, buffer)) = self.pending.remove(&addr) {
            self.on_query_return(dbg, class, buffer)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // At the NtQueryInformationProcess entry, if the class is a debug-detection one, set a one-shot
    // breakpoint at the return site so we can rewrite the output once the kernel has filled it.
    fn on_query_entry(&mut self, dbg: &mut Debugger) -> Result<()> {
        let tid = dbg.current_thread();
        let args = context::read_call_args(tid)?; // [handle, class, buffer, len]
        let class = args[1] as i32;
        if matches!(
            class,
            PROCESS_DEBUG_PORT | PROCESS_DEBUG_OBJECT_HANDLE | PROCESS_DEBUG_FLAGS
        ) {
            let buffer = args[2];
            let return_addr = read_ptr(dbg, context::read_stack_pointer(tid)?)?; // [RSP] at entry
            dbg.set_breakpoint(return_addr)?;
            self.pending.insert(return_addr, (class, buffer));
        }
        Ok(())
    }

    fn on_query_return(&mut self, dbg: &mut Debugger, class: i32, buffer: usize) -> Result<()> {
        match class {
            PROCESS_DEBUG_PORT => write_ptr(dbg, buffer, 0)?, // no debug port
            PROCESS_DEBUG_OBJECT_HANDLE => {
                write_ptr(dbg, buffer, 0)?;
                context::set_return_value(dbg.current_thread(), STATUS_PORT_NOT_SET)?;
            }
            PROCESS_DEBUG_FLAGS => write_u32(dbg, buffer, 1)?, // NO_DEBUG_INHERIT == "not debugged"
            _ => {}
        }
        Ok(())
    }

    // Swallow NtSetInformationThread(ThreadHideFromDebugger): a successful hide would make the
    // target vanish from our debug events. Invalidate the class so the call no-ops.
    fn on_set_thread(&mut self, dbg: &mut Debugger) -> Result<()> {
        let tid = dbg.current_thread();
        let args = context::read_call_args(tid)?; // [handle, class, info, len]
        if args[1] as i32 == THREAD_HIDE_FROM_DEBUGGER {
            context::set_call_arg(tid, 1, INVALID_INFO_CLASS)?;
        }
        Ok(())
    }
}

fn read_ptr(dbg: &Debugger, addr: usize) -> Result<usize> {
    let mut buf = [0u8; PTR];
    nt::read_memory(dbg.process(), addr, &mut buf)?;
    Ok(usize::from_le_bytes(buf))
}

fn write_ptr(dbg: &Debugger, addr: usize, value: usize) -> Result<()> {
    nt::write_memory(dbg.process(), addr, &value.to_le_bytes())
}

fn write_u32(dbg: &Debugger, addr: usize, value: u32) -> Result<()> {
    nt::write_memory(dbg.process(), addr, &value.to_le_bytes())
}
