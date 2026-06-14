//! Parseable artifact filenames `<name-or-base>_<base>_<arch>[_hollow].<ext>`: stable fields a
//! pipeline can split on. The pid and kind live in the run dir and subfolder, not the filename.

#[derive(Clone, Copy)]
pub enum ArtifactKind {
    Main,
    Hidden,
    Chunk,
    Dep,
}

impl ArtifactKind {
    /// Default extension for the kind. main/hidden dump as `exe`, chunks as raw `bin`, deps as
    /// `dll`; deps and main override this with the module's real extension when one is known.
    pub fn ext(self) -> &'static str {
        match self {
            ArtifactKind::Chunk => "bin",
            ArtifactKind::Dep => "dll",
            _ => "exe",
        }
    }

    /// Run-dir subfolder this artifact kind lands in.
    pub fn subdir(self) -> &'static str {
        match self {
            ArtifactKind::Main => "main",
            ArtifactKind::Hidden => "modules",
            ArtifactKind::Chunk => "chunks",
            ArtifactKind::Dep => "deps",
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

/// `<name>_<base>_<arch>[_hollow].<ext>`, or `<base>_<arch>[_hollow].<ext>` when no name was
/// recovered. The base address is always present so names stay unique; pid and kind are encoded by
/// the run dir and subfolder, not repeated here.
pub fn artifact_filename(base: usize, ext: &str, name: Option<&str>, hollow: bool) -> String {
    let flag = if hollow { "_hollow" } else { "" };
    let arch = arch_tag();
    match name {
        Some(n) => format!("{n}_{base:x}_{arch}{flag}.{ext}"),
        None => format!("{base:x}_{arch}{flag}.{ext}"),
    }
}

/// Sanitize an untrusted module name into a safe filename stem, or `None` if nothing usable remains.
/// A mapped path and especially an embedded export Name are attacker-influenced, so take the leaf
/// only (no separator survives), keep a conservative charset, drop edge dots/spaces, cap the length,
/// and reject `..`/empty so a dump write can never escape its folder.
pub fn sanitize_stem(raw: &str) -> Option<String> {
    let leaf = raw.rsplit(['\\', '/']).next().unwrap_or(raw);
    let mapped: String = leaf
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    let trimmed = mapped.trim_matches(|c: char| matches!(c, '.' | ' ' | '_'));
    if trimmed.is_empty() || trimmed.chars().all(|c| c == '.') {
        return None;
    }
    Some(trimmed.to_string())
}

/// Split a module filename (e.g. `kernelbase.dll`) into a sanitized `(stem, extension)`. Used for
/// deps and the main image, which carry a real extension worth keeping.
pub fn split_name(name: &str) -> (Option<String>, Option<String>) {
    let leaf = name.rsplit(['\\', '/']).next().unwrap_or(name);
    match leaf.rsplit_once('.') {
        Some((stem, ext)) => (sanitize_stem(stem), sanitize_ext(ext)),
        None => (sanitize_stem(leaf), None),
    }
}

fn sanitize_ext(raw: &str) -> Option<String> {
    let ext: String = raw
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(8)
        .collect::<String>()
        .to_ascii_lowercase();
    if ext.is_empty() {
        None
    } else {
        Some(ext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_traversal_and_separators() {
        assert_eq!(sanitize_stem("..\\..\\evil").as_deref(), Some("evil"));
        assert_eq!(sanitize_stem("a/b\\c").as_deref(), Some("c"));
    }

    #[test]
    fn sanitize_folds_control_and_unicode() {
        assert_eq!(sanitize_stem("ab\ncd\u{e9}").as_deref(), Some("ab_cd"));
    }

    #[test]
    fn sanitize_caps_length() {
        assert_eq!(sanitize_stem(&"a".repeat(100)).map(|s| s.len()), Some(64));
    }

    #[test]
    fn sanitize_rejects_empty_and_dots() {
        assert!(sanitize_stem("").is_none());
        assert!(sanitize_stem("..").is_none());
        assert!(sanitize_stem("...").is_none());
        assert!(sanitize_stem("   ").is_none());
    }

    #[test]
    fn artifact_filename_keeps_base_with_and_without_name() {
        assert_eq!(
            artifact_filename(0x1e00_0000, "dll", Some("kernelbase"), false),
            format!("kernelbase_1e000000_{}.dll", arch_tag())
        );
        assert_eq!(
            artifact_filename(0x2b0_0000, "exe", None, false),
            format!("2b00000_{}.exe", arch_tag())
        );
    }

    #[test]
    fn split_name_separates_stem_and_ext() {
        let (stem, ext) = split_name("kernelbase.dll");
        assert_eq!(stem.as_deref(), Some("kernelbase"));
        assert_eq!(ext.as_deref(), Some("dll"));
    }
}
