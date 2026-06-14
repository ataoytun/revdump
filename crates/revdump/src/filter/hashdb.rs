use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::Result;

type Hash = [u8; 32];

/// Content-hash database of known-good modules. Because it hashes the on-disk file, not the
/// in-memory image, a packed or hooked module won't match and stays in the dump set; clean system
/// modules match and are filtered out.
pub struct CleanDb {
    path: PathBuf,
    hashes: HashSet<Hash>,
}

impl CleanDb {
    pub fn default_path() -> PathBuf {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("revdump").join("clean.hashes")
    }

    pub fn load() -> CleanDb {
        let path = Self::default_path();
        let hashes = std::fs::read_to_string(&path)
            .map(|text| text.lines().filter_map(parse_hex).collect())
            .unwrap_or_default();
        CleanDb { path, hashes }
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut out = String::with_capacity(self.hashes.len() * 65);
        for h in &self.hashes {
            out.push_str(&to_hex(h));
            out.push('\n');
        }
        std::fs::write(&self.path, out)?;
        Ok(())
    }

    pub fn clear(&mut self) {
        self.hashes.clear();
    }

    pub fn add_dir(&mut self, dir: &Path, recursive: bool) -> usize {
        let before = self.hashes.len();
        for_each_pe(dir, recursive, &mut |p| {
            if let Some(h) = hash_file(p) {
                self.hashes.insert(h);
            }
        });
        self.hashes.len() - before
    }

    pub fn remove_dir(&mut self, dir: &Path, recursive: bool) -> usize {
        let before = self.hashes.len();
        for_each_pe(dir, recursive, &mut |p| {
            if let Some(h) = hash_file(p) {
                self.hashes.remove(&h);
            }
        });
        before - self.hashes.len()
    }

    /// Seed from the system module directories, the bulk of what loads into every process.
    pub fn generate(&mut self) -> usize {
        let windir = std::env::var_os("WINDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
        let before = self.hashes.len();
        for sub in ["System32", "SysWOW64"] {
            self.add_dir(&windir.join(sub), false);
        }
        self.hashes.len() - before
    }

    /// True if the file backing a discovered region (given by its NT device path) is known-good.
    pub fn contains_device_file(&self, device_path: &str) -> bool {
        // GLOBALROOT lets us open \Device\HarddiskVolumeN\... as a normal file for hashing.
        let nt_path = format!("\\\\?\\GLOBALROOT{device_path}");
        hash_file(Path::new(&nt_path)).is_some_and(|h| self.hashes.contains(&h))
    }
}

fn for_each_pe(dir: &Path, recursive: bool, visit: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                for_each_pe(&path, true, visit);
            }
        } else if is_pe_extension(&path) {
            visit(&path);
        }
    }
}

fn is_pe_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    // .mui are resource-only PEs that surface as benign "hidden modules"; include them so the DB
    // can exclude them.
    matches!(
        ext.as_deref(),
        Some("dll" | "exe" | "sys" | "ocx" | "cpl" | "scr" | "drv" | "mui")
    )
}

fn hash_file(path: &Path) -> Option<Hash> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().into())
}

fn to_hex(hash: &Hash) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn parse_hex(line: &str) -> Option<Hash> {
    let line = line.trim();
    if line.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(line.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
