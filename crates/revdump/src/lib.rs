//! revdump — user-mode reverse-engineering memory dumper (shared core).
//!
//! Two binaries build from this crate: `revdump32` (i686) and `revdump64` (x86_64), each
//! dumping its own architecture natively to sidestep WOW64 cross-bitness. All logic lives here;
//! the binaries are thin arch-locked shims.

#[macro_use]
mod log;
mod access;
mod cli;
mod debug;
mod discovery;
mod error;
mod filter;
mod nt;
mod output;
mod reconstruct;
mod triggers;

use windows_sys::Win32::Foundation::HANDLE;

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
        cli::Action::ManageDb(db) => manage_db(db),
        cli::Action::Dump(spec) => dispatch_dump(spec),
    }
}

fn manage_db(action: cli::DbAction) -> Result<i32> {
    let mut db = filter::hashdb::CleanDb::load();
    match action {
        cli::DbAction::Gen => {
            let added = db.generate();
            db.save()?;
            println!(
                "clean-hash DB: hashed {added} system modules (total {})",
                db.len()
            );
        }
        cli::DbAction::Add(dir) => {
            let added = db.add_dir(&dir, true);
            db.save()?;
            println!(
                "clean-hash DB: added {added} from {} (total {})",
                dir.display(),
                db.len()
            );
        }
        cli::DbAction::Rem(dir) => {
            let removed = db.remove_dir(&dir, true);
            db.save()?;
            println!("clean-hash DB: removed {removed} (total {})", db.len());
        }
        cli::DbAction::Clean => {
            db.clear();
            db.save()?;
            println!("clean-hash DB: cleared");
        }
    }
    Ok(0)
}

fn dispatch_dump(spec: cli::DumpSpec) -> Result<i32> {
    vlog!(2, "output dir: {}", spec.out.display());
    if spec.minidump {
        vlog!(1, "minidump export requested (pending later milestone)");
    }
    match (&spec.scope, spec.addr, spec.closemon) {
        // The single-PID path: discovery, reconstruction, dump + manifest (+ optional minidump).
        (cli::Scope::Pid(pid), None, false) => dump_pid(*pid, &spec.out, spec.minidump),
        // -a: attach as a debugger and dump when execution reaches the address.
        (cli::Scope::Pid(pid), Some(addr), false) => {
            dump_on_breakpoint(*pid, addr as usize, &spec.out, spec.minidump)
        }
        // -closemon -pid X: dump X just before it exits.
        (cli::Scope::Pid(pid), None, true) => run_closemon(*pid, &spec.out, spec.minidump),
        // -system: dump every accessible process's main image.
        (cli::Scope::System, None, false) => run_system_sweep(&spec.out, spec.minidump),
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

// Dump a target by PID: acquire privilege, open it, and run the full dump pipeline.
fn dump_pid(pid: u32, out: &std::path::Path, minidump: bool) -> Result<i32> {
    enable_se_debug();
    let proc = access::open::open_process(pid)?;
    dump_target(proc.handle(), pid, out, minidump)
}

fn enable_se_debug() {
    match access::privilege::enable_se_debug() {
        Ok(held) => vlog!(1, "SeDebugPrivilege held: {held}"),
        Err(err) => vlog!(1, "SeDebugPrivilege: {err}"),
    }
}

// Attach as a debugger, arm a software breakpoint at `addr`, and dump when execution reaches it.
fn dump_on_breakpoint(pid: u32, addr: usize, out: &std::path::Path, minidump: bool) -> Result<i32> {
    enable_se_debug();
    let mut dbg = debug::engine::Debugger::attach(pid)?;
    println!("attached to pid {pid}; arming breakpoint at {addr:#x}");

    let exit_code = loop {
        match dbg.cont()? {
            debug::engine::Stop::InitialBreak => {
                // Anti-debug PEB patches (M7) will hook in here, before TLS/EP.
                dbg.set_breakpoint(addr)?;
                vlog!(1, "initial loader breakpoint reached; breakpoint armed");
            }
            debug::engine::Stop::Breakpoint(hit) => {
                println!("breakpoint hit at {hit:#x}; dumping");
                let code = dump_target(dbg.process(), pid, out, minidump)?;
                break code;
            }
            debug::engine::Stop::Exited(code) => {
                println!("target exited (code {code}) before the breakpoint was reached");
                break 1;
            }
        }
    };
    dbg.detach()?;
    Ok(exit_code)
}

// -closemon: catch a process just before it exits and dump it.
fn run_closemon(pid: u32, out: &std::path::Path, minidump: bool) -> Result<i32> {
    enable_se_debug();
    println!("monitoring pid {pid} for termination");
    let caught = triggers::terminate::monitor(pid, |handle| {
        println!("pid {pid} is exiting; dumping before termination");
        dump_target(handle, pid, out, minidump).map(|_| ())
    })?;
    if !caught {
        println!("pid {pid} exited before it could be caught");
    }
    Ok(if caught { 0 } else { 1 })
}

// -system: dump every accessible process's main image.
fn run_system_sweep(out: &std::path::Path, minidump: bool) -> Result<i32> {
    enable_se_debug();
    let me = std::process::id();
    let mut dumped = 0u32;
    let mut skipped = 0u32;
    for pid in triggers::sweep::enumerate_pids() {
        if pid == me {
            continue;
        }
        match sweep_dump_main(pid, out, minidump) {
            Ok(()) => {
                dumped += 1;
                vlog!(1, "dumped pid {pid}");
            }
            Err(err) => {
                skipped += 1;
                vlog!(2, "skipped pid {pid}: {err}");
            }
        }
    }
    println!("system sweep: dumped {dumped}, skipped {skipped}");
    Ok(0)
}

// Lightweight per-process dump for the sweep: just the main image (with import reconstruction if
// the directory was erased) — no discovery diff or chunk scan, to keep a whole-system pass quick.
fn sweep_dump_main(pid: u32, out: &std::path::Path, minidump: bool) -> Result<()> {
    let proc = access::open::open_process(pid)?;
    let reader = access::reader::ProcessReader::new(proc.handle());
    let main_base = nt::read_peb(proc.handle())?.image_base_address as usize;

    let mut artifact = reconstruct::dump_module_image(&reader, main_base)?;
    if !reconstruct::imports::has_import_directory(&artifact.bytes) {
        let modules = discovery::peb::enumerate_loader_modules(proc.handle())?;
        let catalog = reconstruct::exports::ExportCatalog::build(&reader, &modules);
        reconstruct::imports::rebuild_imports(&mut artifact.bytes, &catalog);
    }

    std::fs::create_dir_all(out)?;
    let name = output::naming::filename(pid, main_base, output::naming::ArtifactKind::Main, false);
    std::fs::write(out.join(name), &artifact.bytes)?;
    if minidump {
        let _ =
            output::minidump::write_minidump(proc.handle(), pid, &out.join(format!("{pid}.dmp")));
    }
    Ok(())
}

// Discovery + reconstruction + output against an already-open target handle (a freshly opened
// process, or a handle from the debug-event loop).
fn dump_target(process: HANDLE, pid: u32, out: &std::path::Path, minidump: bool) -> Result<i32> {
    let reader = access::reader::ProcessReader::new(process);
    let report = discovery::scan_process(process, &reader)?;

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

    let clean_db = filter::hashdb::CleanDb::load();
    if clean_db.is_empty() {
        vlog!(
            1,
            "clean-hash DB empty; run `-db gen` to exclude known-good modules"
        );
    }
    // The export catalog is reused for both import reconstruction and chunk noise filtering, and
    // is expensive to build, so create it lazily on first need.
    let mut catalog: Option<reconstruct::exports::ExportCatalog> = None;
    let ptr = core::mem::size_of::<usize>();
    let mut skipped_known = 0usize;
    let mut skipped_noise = 0usize;

    // Main image — the primary unpacking target.
    let main_base = nt::read_peb(process)?.image_base_address as usize;
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
        let cat = catalog.get_or_insert_with(|| {
            reconstruct::exports::ExportCatalog::build(&reader, &report.loader_modules)
        });
        match reconstruct::imports::rebuild_imports(&mut main.bytes, cat) {
            Some(s) => {
                println!(
                    "  reconstructed imports: {} modules, {} functions (catalog {} exports)",
                    s.modules,
                    s.functions,
                    cat.len()
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
        // Skip file-backed mappings that hash to a known-good module (e.g. resource DLLs).
        if let Some(device) = &m.mapped_path {
            if clean_db.contains_device_file(device) {
                skipped_known += 1;
                continue;
            }
        }
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
        // Drop chunks that don't reference real imports — almost always data, not code.
        let cat = catalog.get_or_insert_with(|| {
            reconstruct::exports::ExportCatalog::build(&reader, &report.loader_modules)
        });
        if !filter::noise::is_plausible_code(&a.bytes, cat, ptr) {
            skipped_noise += 1;
            continue;
        }
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
        "wrote {} artifact(s) + manifest to {} (skipped {skipped_known} known-good, \
         {skipped_noise} noise)",
        manifest.artifacts.len(),
        out.display()
    );

    if minidump {
        let dmp = out.join(format!("{pid}.dmp"));
        match output::minidump::write_minidump(process, pid, &dmp) {
            Ok(()) => println!("wrote minidump -> {}", dmp.display()),
            Err(err) => eprintln!("revdump: minidump failed: {err}"),
        }
    }
    Ok(0)
}
