//! revdump — user-mode reverse-engineering memory dumper (shared core).
//!
//! Two binaries build from this crate: `revdump32` (i686) and `revdump64` (x86_64), each
//! dumping its own architecture natively to sidestep WOW64 cross-bitness. All logic lives here;
//! the binaries are thin arch-locked shims.

#[macro_use]
mod log;
mod access;
mod cli;
mod discovery;
mod error;
mod nt;
mod output;
mod reconstruct;

pub use error::{RegionOutcome, Result, RevError};

/// Shared entry point for both arch binaries. Returns a process exit code.
pub fn run() -> i32 {
    match try_run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("revdump: error: {err}");
            // Match clap's convention so usage errors share one exit code regardless of which
            // layer rejected them.
            match err {
                RevError::Cli(_) => 2,
                _ => 1,
            }
        }
    }
}

fn try_run() -> Result<i32> {
    let cli = cli::parse();
    log::set_verbosity(cli.verbose);
    vlog!(2, "parsed CLI: {cli:?}");
    dispatch(cli.into_action()?)
}

fn dispatch(action: cli::Action) -> Result<i32> {
    // M0: the argument surface and validation are wired; per-layer dispatch lands in later
    // milestones. Each arm reports the resolved request honestly rather than pretending to run.
    match action {
        cli::Action::ManageDb(db) => {
            let what = match db {
                cli::DbAction::Gen => "gen".to_string(),
                cli::DbAction::Clean => "clean".to_string(),
                cli::DbAction::Add(dir) => format!("add {}", dir.display()),
                cli::DbAction::Rem(dir) => format!("rem {}", dir.display()),
            };
            eprintln!("revdump: clean-hash DB management not implemented yet (scaffold): {what}");
            Ok(0)
        }
        cli::Action::Dump(spec) => dispatch_dump(spec),
    }
}

fn dispatch_dump(spec: cli::DumpSpec) -> Result<i32> {
    vlog!(2, "output dir: {}", spec.out.display());
    if spec.minidump {
        vlog!(1, "minidump export requested (pending later milestone)");
    }
    match (&spec.scope, spec.addr, spec.closemon) {
        // The single-PID path: discovery, reconstruction, dump + manifest (+ optional minidump).
        (cli::Scope::Pid(pid), None, false) => dump_pid(*pid, &spec.out, spec.minidump),
        _ => {
            let what = match &spec.scope {
                cli::Scope::Pid(p) => format!("pid {p}"),
                cli::Scope::NameRegex(rx) => format!("name ~ /{rx}/"),
                cli::Scope::System => "system".to_string(),
            };
            eprintln!(
                "revdump: dump mode for {what} (addr={:?}, closemon={}) not implemented yet",
                spec.addr, spec.closemon
            );
            Ok(0)
        }
    }
}

// M3: discovery summary plus a memory-aligned dump of the main image to the output dir.
fn dump_pid(pid: u32, out: &std::path::Path, minidump: bool) -> Result<i32> {
    match access::privilege::enable_se_debug() {
        Ok(held) => vlog!(1, "SeDebugPrivilege held: {held}"),
        Err(err) => vlog!(1, "SeDebugPrivilege: {err}"),
    }

    let proc = access::open::open_process(pid)?;
    let reader = access::reader::ProcessReader::new(&proc);
    let report = discovery::scan_process(proc.handle(), &reader)?;

    let exec_regions = report.regions.iter().filter(|r| r.is_executable()).count();
    let suspicious: Vec<_> = report
        .module_diffs
        .iter()
        .filter(|d| d.is_suspicious())
        .collect();
    println!(
        "pid {pid}: regions={} (exec {exec_regions}) loader_modules={} \
         hidden_modules={} loose_code_chunks={} modified_modules={}",
        report.regions.len(),
        report.loader_modules.len(),
        report.hidden_modules.len(),
        report.code_chunks.len(),
        suspicious.len(),
    );

    for m in &report.hidden_modules {
        let path = m
            .mapped_path
            .as_deref()
            .map(|p| format!(" [{p}]"))
            .unwrap_or_default();
        let bits = if m.is_pe32_plus { 64 } else { 32 };
        println!(
            "  hidden module @ {:#x} size {:#x} {:?} pe{bits}{path}",
            m.base, m.size, m.kind
        );
    }
    for d in &suspicious {
        let mut flags = Vec::new();
        if let Some(name) = &d.name_mismatch {
            flags.push(format!("name!=mapped({name})"));
        }
        if d.image_base_mismatch {
            flags.push("imagebase-mismatch".into());
        }
        if d.header_modified {
            flags.push("header-modified".into());
        }
        if !d.hooks.is_empty() {
            flags.push(format!(
                "{} hooks / {} bytes",
                d.hooks.len(),
                d.modified_bytes
            ));
        }
        println!(
            "  modified module {} @ {:#x}: {}",
            d.name,
            d.base,
            flags.join(", ")
        );
        for h in &d.hooks {
            vlog!(2, "    hook @ rva {:#x} len {}", h.rva, h.len);
        }
    }
    if log::verbosity() >= 1 {
        for c in &report.code_chunks {
            println!(
                "  loose code @ {:#x} size {:#x} prot {:#x}",
                c.base, c.size, c.protect
            );
        }
        for module in &report.loader_modules {
            vlog!(
                2,
                "  module {:#x} +{:#x} {}",
                module.base,
                module.size,
                module.base_name
            );
        }
        for d in &report.module_diffs {
            if let Some(note) = &d.note {
                vlog!(2, "  module {} @ {:#x} not diffed: {note}", d.name, d.base);
            }
        }
    }

    std::fs::create_dir_all(out)?;
    let mut artifacts = Vec::new();

    // Main image — the primary unpacking target.
    let main_base = nt::read_peb(proc.handle())?.image_base_address as usize;
    let main_hollowed = report
        .module_diffs
        .iter()
        .find(|d| d.base == main_base)
        .is_some_and(|d| d.is_hollowed());
    let mut main = reconstruct::dump_module_image(&reader, main_base)?;

    // Packers erase the import directory after the loader binds the IAT; rebuild it so the dump
    // lands in IDA with named imports.
    let (imports_state, confidence) = if reconstruct::imports::has_import_directory(&main.bytes) {
        ("original".to_string(), "high")
    } else {
        let catalog = reconstruct::exports::ExportCatalog::build(&reader, &report.loader_modules);
        match reconstruct::imports::rebuild_imports(&mut main.bytes, &catalog) {
            Some(s) => {
                println!(
                    "  reconstructed imports: {} modules, {} functions (catalog {} exports)",
                    s.modules,
                    s.functions,
                    catalog.len()
                );
                (
                    format!(
                        "reconstructed: {} modules, {} functions",
                        s.modules, s.functions
                    ),
                    "medium",
                )
            }
            None => ("none".to_string(), "low"),
        }
    };

    let main_name = output::naming::filename(
        pid,
        main_base,
        output::naming::ArtifactKind::Main,
        main_hollowed,
    );
    std::fs::write(out.join(&main_name), &main.bytes)?;
    artifacts.push(output::manifest::Artifact {
        file: main_name,
        kind: "main".into(),
        base: format!("{main_base:#x}"),
        real_base: format!("{main_base:#x}"),
        size: main.bytes.len(),
        original_protection: None,
        hidden: false,
        hollowed: main_hollowed,
        unreadable_pages: main.unreadable_pages,
        header: "original".into(),
        imports: imports_state,
        confidence: confidence.into(),
    });
    println!(
        "dumped main image @ {main_base:#x} ({} bytes, {} unreadable pages){}",
        main.bytes.len(),
        main.unreadable_pages,
        if main_hollowed { " [hollowed]" } else { "" }
    );

    // Hidden modules (real header if present, else a synthesized one).
    for m in &report.hidden_modules {
        let (bytes, pages, header) = match reconstruct::dump_module_image(&reader, m.base) {
            Ok(a) => (a.bytes, a.unreadable_pages, "original"),
            Err(_) => {
                let a = reconstruct::dump_code_chunk(&reader, m.base, m.size);
                (a.bytes, a.unreadable_pages, "synthesized")
            }
        };
        let name =
            output::naming::filename(pid, m.base, output::naming::ArtifactKind::Hidden, false);
        std::fs::write(out.join(&name), &bytes)?;
        let synthesized = header == "synthesized";
        artifacts.push(output::manifest::Artifact {
            file: name,
            kind: "hidden".into(),
            base: format!("{:#x}", m.base),
            real_base: format!("{:#x}", m.base),
            size: bytes.len(),
            original_protection: None,
            hidden: true,
            hollowed: false,
            unreadable_pages: pages,
            header: header.into(),
            imports: if synthesized { "none" } else { "original" }.into(),
            confidence: if synthesized { "low" } else { "medium" }.into(),
        });
    }

    // Loose code chunks (always synthesized).
    for c in &report.code_chunks {
        let a = reconstruct::dump_code_chunk(&reader, c.base, c.size);
        let name =
            output::naming::filename(pid, c.base, output::naming::ArtifactKind::Chunk, false);
        std::fs::write(out.join(&name), &a.bytes)?;
        artifacts.push(output::manifest::Artifact {
            file: name,
            kind: "chunk".into(),
            base: format!("{:#x}", c.base),
            real_base: format!("{:#x}", c.base),
            size: a.bytes.len(),
            original_protection: Some(format!("{:#x}", c.protect)),
            hidden: false,
            hollowed: false,
            unreadable_pages: a.unreadable_pages,
            header: "synthesized".into(),
            imports: "none".into(),
            confidence: "low".into(),
        });
    }

    let manifest = output::manifest::Manifest {
        pid,
        arch: output::naming::arch_tag().into(),
        artifacts,
    };
    manifest.write(&out.join(format!("{pid}_manifest.json")))?;
    println!(
        "wrote {} artifact(s) + manifest to {}",
        manifest.artifacts.len(),
        out.display()
    );

    if minidump {
        let dmp = out.join(format!("{pid}.dmp"));
        match output::minidump::write_minidump(proc.handle(), pid, &dmp) {
            Ok(()) => println!("wrote minidump -> {}", dmp.display()),
            Err(err) => eprintln!("revdump: minidump failed: {err}"),
        }
    }
    Ok(0)
}
