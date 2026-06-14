//! Parseable artifact filenames `pid_base_arch_kind[_hollow].ext`: stable fields a pipeline can
//! split on without guessing.

#[derive(Clone, Copy)]
pub enum ArtifactKind {
    Main,
    Hidden,
    Chunk,
}

impl ArtifactKind {
    pub fn label(self) -> &'static str {
        match self {
            ArtifactKind::Main => "main",
            ArtifactKind::Hidden => "hidden",
            ArtifactKind::Chunk => "chunk",
        }
    }

    fn ext(self) -> &'static str {
        match self {
            ArtifactKind::Chunk => "bin",
            _ => "exe",
        }
    }

    /// Run-dir subfolder this artifact kind lands in.
    pub fn subdir(self) -> &'static str {
        match self {
            ArtifactKind::Main => "main",
            ArtifactKind::Hidden => "modules",
            ArtifactKind::Chunk => "chunks",
        }
    }
}

pub fn arch_tag() -> &'static str {
    if cfg!(target_pointer_width = "64") {
        "x64"
    } else {
        "x86"
    }
}

pub fn filename(pid: u32, base: usize, kind: ArtifactKind, hollow: bool) -> String {
    let flag = if hollow { "_hollow" } else { "" };
    format!(
        "{pid}_{base:x}_{}_{}{flag}.{}",
        arch_tag(),
        kind.label(),
        kind.ext()
    )
}
