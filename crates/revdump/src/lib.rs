//! revdump — user-mode reverse-engineering memory dumper (shared core).
//!
//! Two binaries build from this crate: `revdump32` (i686) and `revdump64` (x86_64), each
//! dumping its own architecture natively to sidestep WOW64 cross-bitness. All logic lives here;
//! the binaries are thin arch-locked shims.

#[macro_use]
mod log;
mod access;
mod cli;
mod error;
mod nt;

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
        // M1: exercise privilege + open + PEB/memory reads end-to-end against a single PID.
        (cli::Scope::Pid(pid), None, false) => probe_pid(*pid),
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

// M1 access-layer probe — also the 32->32 WOW64 verification path. Replaced by the real dump
// pipeline from M3 on.
fn probe_pid(pid: u32) -> Result<i32> {
    match access::privilege::enable_se_debug() {
        Ok(held) => vlog!(1, "SeDebugPrivilege held: {held}"),
        Err(err) => vlog!(1, "SeDebugPrivilege: {err}"),
    }

    let proc = access::open::open_process(pid)?;
    let reader = access::reader::ProcessReader::new(&proc);

    let peb_base = nt::peb_base(proc.handle())?;
    let peb = nt::read_peb(proc.handle())?;
    let image_base = peb.image_base_address as usize;

    // Pull the PE header page through the fault-tolerant reader; a guarded page won't abort.
    let (header, gaps) =
        access::reader::read_best_effort(&reader, image_base, access::reader::PAGE_SIZE);
    let mz = header.starts_with(b"MZ");

    println!(
        "pid {pid}: PEB={peb_base:#x} ImageBase={image_base:#x} \
         BeingDebugged={} NtGlobalFlag={:#x} MZ@ImageBase={mz} unreadable_pages={}",
        peb.being_debugged,
        peb.nt_global_flag,
        gaps.len()
    );
    Ok(0)
}
