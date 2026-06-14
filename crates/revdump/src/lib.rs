//! revdump — user-mode reverse-engineering memory dumper (shared core).
//!
//! Two binaries build from this crate: `revdump32` (i686) and `revdump64` (x86_64), each
//! dumping its own architecture natively to sidestep WOW64 cross-bitness. All logic lives here;
//! the binaries are thin arch-locked shims.

#[macro_use]
mod log;
mod cli;
mod error;

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
        cli::Action::Dump(spec) => {
            let target = match &spec.scope {
                cli::Scope::Pid(pid) => format!("pid {pid}"),
                cli::Scope::NameRegex(rx) => format!("name ~ /{rx}/"),
                cli::Scope::System => "system".to_string(),
            };
            eprintln!(
                "revdump: dumping not implemented yet (scaffold): target={target} addr={:?} \
                 closemon={} minidump={} out={}",
                spec.addr,
                spec.closemon,
                spec.minidump,
                spec.out.display()
            );
            Ok(0)
        }
    }
}
