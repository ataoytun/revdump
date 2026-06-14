use std::path::Path;

use serde::Serialize;

use crate::error::{Result, RevError};

/// Per-dump-session sidecar: one record per artifact so automation can consume the run without
/// re-parsing the PEs.
#[derive(Serialize)]
pub struct Manifest {
    pub pid: u32,
    pub arch: String,
    pub artifacts: Vec<Artifact>,
}

#[derive(Serialize)]
pub struct Artifact {
    pub file: String,
    pub kind: String,
    pub base: String,
    /// Real ASLR load base the dump was captured at (equals `base` for memory-aligned dumps).
    pub real_base: String,
    pub size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_protection: Option<String>,
    pub hidden: bool,
    pub hollowed: bool,
    pub unreadable_pages: usize,
    /// "original" or "synthesized".
    pub header: String,
    /// "original", "reconstructed: …", or "none".
    pub imports: String,
    /// Rough confidence the artifact is analysis-ready: "high" | "medium" | "low".
    pub confidence: String,
}

impl Manifest {
    pub fn write(&self, path: &Path) -> Result<()> {
        let json =
            serde_json::to_string_pretty(self).map_err(|e| RevError::Output(e.to_string()))?;
        std::fs::write(path, json)?;
        Ok(())
    }
}
