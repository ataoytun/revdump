use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, RevError>;

/// Fatal errors — anything that aborts the current operation. Per-region failures use
/// [`RegionOutcome`] instead so a single bad page never sinks the whole dump.
#[derive(Debug, Error)]
pub enum RevError {
    #[error("invalid arguments: {0}")]
    Cli(String),

    #[error("could not acquire privilege: {0}")]
    Privilege(String),

    #[error("cannot access target: {0}")]
    Access(String),

    #[error("target is protected ({0}); cannot dump from user mode")]
    Protected(String),

    #[error("wrong architecture: {0}")]
    ArchMismatch(String),

    #[error("discovery failed: {0}")]
    Discovery(String),

    #[error("reconstruction failed: {0}")]
    Reconstruct(String),

    #[error("output failed: {0}")]
    Output(String),

    #[error("{call} failed (NTSTATUS {status:#010x})")]
    Nt { call: &'static str, status: u32 },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Outcome of processing one memory region. The dump loop collects these so a guarded or
/// unreadable region degrades only itself; the manifest then reflects exactly what succeeded.
#[derive(Debug)]
pub enum RegionOutcome {
    Dumped { path: PathBuf },
    Skipped { reason: String },
    Failed { error: String },
}
