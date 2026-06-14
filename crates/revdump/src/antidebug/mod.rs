//! Packer anti-analysis neutralization, driven entirely by the external debugger (no injection).
//! PEB/heap patches and the syscall-result interception of the debug-detection NTAPI classes are
//! applied at the initial loader breakpoint. That breakpoint precedes the first TLS callback / the
//! entry point only when revdump *launches* the target (--launch); on attach (--oep/-a on a
//! running pid) it fires after startup, so pre-EP checks have already run.

pub mod intercept;
pub mod peb_patch;
