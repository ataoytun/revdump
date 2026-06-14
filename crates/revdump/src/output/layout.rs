//! Per-run output tree: `<base>/<image>_<pid>_<YYYYMMDD-HHMMSS>/` with per-kind subfolders created
//! lazily (so a kind with no artifacts leaves no empty directory). The manifest sits at the root.

use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

use crate::error::Result;
use crate::output::naming::ArtifactKind;

/// Local wall-clock stamp `YYYYMMDD-HHMMSS`: zero-padded, sortable, and free of separators a shell
/// would split on.
pub fn timestamp_local() -> String {
    // SAFETY: GetLocalTime fills a SYSTEMTIME we own and takes no input buffers.
    let st = unsafe {
        let mut st: SYSTEMTIME = core::mem::zeroed();
        GetLocalTime(&mut st);
        st
    };
    format_stamp(
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
    )
}

fn format_stamp(year: u16, month: u16, day: u16, hour: u16, min: u16, sec: u16) -> String {
    format!("{year:04}{month:02}{day:02}-{hour:02}{min:02}{sec:02}")
}

// Keep the run-dir name to a portable set; fold anything else to '_'.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `<image>_<pid>_<stamp>`. The pid keeps the directory unique when two same-named processes are
/// dumped in the same second, so their manifests never collide.
pub fn run_dir_name(image_name: &str, pid: u32, stamp: &str) -> String {
    format!("{}_{pid}_{stamp}", sanitize(image_name))
}

/// One dump run's output tree under `base`.
pub struct RunLayout {
    root: PathBuf,
}

impl RunLayout {
    pub fn new(base: &Path, image_name: &str, pid: u32, stamp: &str) -> RunLayout {
        RunLayout {
            root: base.join(run_dir_name(image_name, pid, stamp)),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn create_root(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        Ok(())
    }

    /// Subfolder for `kind`, created on demand. Call it only when about to write an artifact of that
    /// kind, so a kind with nothing to dump leaves no empty directory behind.
    pub fn dir(&self, kind: ArtifactKind) -> Result<PathBuf> {
        let dir = self.root.join(kind.subdir());
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_is_zero_padded_and_sortable() {
        assert_eq!(format_stamp(2026, 6, 14, 9, 5, 3), "20260614-090503");
        assert_eq!(format_stamp(2026, 12, 31, 23, 59, 59), "20261231-235959");
    }

    #[test]
    fn run_dir_name_carries_pid() {
        assert_eq!(
            run_dir_name("svchost.exe", 1234, "20260614-090503"),
            "svchost.exe_1234_20260614-090503"
        );
    }

    #[test]
    fn sanitize_folds_unsafe_chars() {
        assert_eq!(sanitize("My App.exe"), "My_App.exe");
        assert_eq!(sanitize("a/b\\c:d"), "a_b_c_d");
        assert_eq!(sanitize("ok-name_1.dll"), "ok-name_1.dll");
    }
}
