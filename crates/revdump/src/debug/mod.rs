//! External Win32 debugger engine that drives the trigger and anti-debug layers — attach, run the
//! debug-event loop, place software/context breakpoints, and surface the initial loader
//! breakpoint. No code is injected into the target.

pub mod context;
pub mod engine;
