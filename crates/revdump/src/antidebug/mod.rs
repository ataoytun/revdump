//! Packer anti-analysis neutralization, driven entirely by the external debugger (no injection).
//! PEB/heap patches applied at the initial loader breakpoint (before TLS callbacks / the entry
//! point); syscall-result interception of the debug-detection NTAPI classes follows.

pub mod intercept;
pub mod peb_patch;
