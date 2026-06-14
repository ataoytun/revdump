//! Triggers layer: decide *when* to dump. Terminate-monitor and the full-system sweep live here;
//! the TLS-callback, new-executable-allocation, and OEP triggers build on the shared execmem state
//! machine. Each is driven by the external debugger engine, with orchestration in the crate root
//! so the trigger code stays free of the dump pipeline.

pub mod execmem;
pub mod oep;
pub mod sweep;
pub mod terminate;
