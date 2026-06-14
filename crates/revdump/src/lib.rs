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
        // Through M2 the single-PID path runs a discovery scan; reconstruction lands at M3.
        (cli::Scope::Pid(pid), None, false) => dump_pid(*pid, &spec.out),
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
fn dump_pid(pid: u32, out: &std::path::Path) -> Result<i32> {
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
    let main_base = nt::read_peb(proc.handle())?.image_base_address as usize;
    let mut artifact = reconstruct::dump_module_image(&reader, main_base)?;
    // Packers erase the import directory after the loader binds the IAT; rebuild it so the dump
    // lands in IDA with named imports.
    if !reconstruct::imports::has_import_directory(&artifact.bytes) {
        let catalog = reconstruct::exports::ExportCatalog::build(&reader, &report.loader_modules);
        match reconstruct::imports::rebuild_imports(&mut artifact.bytes, &catalog) {
            Some(stats) => println!(
                "  reconstructed imports: {} modules, {} functions (catalog {} exports)",
                stats.modules,
                stats.functions,
                catalog.len()
            ),
            None => vlog!(1, "  no resolvable IAT found; left import directory empty"),
        }
    }
    let path = out.join(format!("{pid}_{:x}_main.exe", artifact.base));
    std::fs::write(&path, &artifact.bytes)?;
    println!(
        "dumped main image @ {main_base:#x} -> {} ({} bytes, {} unreadable pages)",
        path.display(),
        artifact.bytes.len(),
        artifact.unreadable_pages
    );

    // Novel code the loader doesn't account for: hidden modules (real header if present, else a
    // synthesized one) and loose chunks (always synthesized).
    for m in &report.hidden_modules {
        let chunk = match reconstruct::dump_module_image(&reader, m.base) {
            Ok(a) => a,
            Err(_) => reconstruct::dump_code_chunk(&reader, m.base, m.size),
        };
        let p = out.join(format!("{pid}_{:x}_hidden.bin", m.base));
        std::fs::write(&p, &chunk.bytes)?;
        vlog!(1, "dumped hidden module @ {:#x} -> {}", m.base, p.display());
    }
    for c in &report.code_chunks {
        let chunk = reconstruct::dump_code_chunk(&reader, c.base, c.size);
        let p = out.join(format!("{pid}_{:x}_chunk.bin", c.base));
        std::fs::write(&p, &chunk.bytes)?;
        vlog!(1, "dumped loose code @ {:#x} -> {}", c.base, p.display());
    }
    println!(
        "dumped {} hidden module(s) and {} loose chunk(s) to {}",
        report.hidden_modules.len(),
        report.code_chunks.len(),
        out.display()
    );
    Ok(0)
}
