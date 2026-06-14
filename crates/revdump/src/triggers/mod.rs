//! Layer 4 — triggers: decide *when* to dump. Terminate-monitor and the full-system sweep here;
//! TLS-callback / new-executable-allocation / OEP triggers build on the shared execmem state
//! machine. Each is driven by the external debugger engine — orchestration lives in the crate
//! root so the trigger code stays free of the dump pipeline.

pub mod sweep;
pub mod terminate;
