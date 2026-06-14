use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, Parser};

use crate::error::{Result, RevError};

#[derive(Debug, Parser)]
#[command(
    name = "revdump",
    version,
    about = "User-mode reverse-engineering memory dumper",
    long_about = "Dumps and reconstructs process memory into IDA/Ghidra-loadable PE files.\n\n\
Mirrors Process Dump's CLI: the legacy single-dash long flags (-pid, -system, -closemon, -db, \
-minidump, -oep, -launch, -hide) are accepted alongside their --double-dash forms."
)]
pub struct Cli {
    /// Dump a process by PID (decimal, or 0x-prefixed hex)
    #[arg(long = "pid", value_name = "PID", value_parser = parse_u32_auto)]
    pub pid: Option<u32>,

    /// Dump all processes whose name matches this regex
    #[arg(short = 'p', long = "name-regex", value_name = "REGEX")]
    pub name: Option<String>,

    /// Dump all accessible processes
    #[arg(long = "system")]
    pub system: bool,

    /// Dump a specific address in the target (requires --pid)
    #[arg(short = 'a', long = "addr", value_name = "ADDR", value_parser = parse_u64_auto)]
    pub addr: Option<u64>,

    /// Output directory
    #[arg(short = 'o', long = "out", value_name = "PATH", default_value = ".")]
    pub out: PathBuf,

    /// Terminate-monitor: dump processes just before they exit (combine with a scope, or run
    /// bare for system-wide best-effort monitoring)
    #[arg(long = "closemon")]
    pub closemon: bool,

    /// Manage the clean-hash database: gen | add <dir> | rem <dir> | clean
    #[arg(long = "db", value_name = "OP", num_args = 1..=2)]
    pub db: Option<Vec<String>>,

    /// Also write a minidump (.dmp) alongside the RE-oriented PE dumps
    #[arg(long = "minidump")]
    pub minidump: bool,

    /// Detect a packed target's original entry point and dump there (requires --pid or --launch)
    #[arg(long = "oep")]
    pub oep: bool,

    /// Launch an executable under the debugger and dump it (combine with --hide / --oep)
    #[arg(long = "launch", value_name = "PATH")]
    pub launch: Option<PathBuf>,

    /// Neutralize common anti-debug checks (BeingDebugged, NtGlobalFlag, heap flags) at the
    /// initial loader breakpoint, before TLS callbacks / the entry point
    #[arg(long = "hide")]
    pub hide: bool,

    /// Verbose output (repeat for more)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,
}

pub fn parse() -> Cli {
    match Cli::try_parse_from(normalize(std::env::args_os())) {
        Ok(cli) => cli,
        Err(err) => err.exit(),
    }
}

fn normalize<I: IntoIterator<Item = OsString>>(raw: I) -> Vec<OsString> {
    raw.into_iter().map(remap_legacy_flag).collect()
}

// Process Dump spells its long flags single-dash (-pid, -system, ...); clap would otherwise read
// those as bundled short flags, so rewrite the known ones to --double-dash before clap sees them.
// Single-char flags (-p, -a, -o, -v) are genuine shorts and pass through untouched.
fn remap_legacy_flag(arg: OsString) -> OsString {
    let Some(s) = arg.to_str() else { return arg };
    let (head, value) = match s.split_once('=') {
        Some((head, value)) => (head, Some(value)),
        None => (s, None),
    };
    let mapped = match head {
        "-pid" => "--pid",
        "-system" => "--system",
        "-closemon" => "--closemon",
        "-db" => "--db",
        "-minidump" => "--minidump",
        "-oep" => "--oep",
        "-launch" => "--launch",
        "-hide" => "--hide",
        _ => return arg,
    };
    match value {
        Some(value) => OsString::from(format!("{mapped}={value}")),
        None => OsString::from(mapped),
    }
}

/// A validated command, resolved from the raw flag surface.
#[derive(Debug)]
pub enum Action {
    ManageDb(DbAction),
    Dump(DumpSpec),
}

#[derive(Debug)]
pub enum DbAction {
    Gen,
    Add(PathBuf),
    Rem(PathBuf),
    Clean,
}

#[derive(Debug)]
pub enum Scope {
    Pid(u32),
    NameRegex(String),
    System,
    /// Launch this command under the debugger.
    Launch(String),
}

#[derive(Debug)]
pub struct DumpSpec {
    pub scope: Scope,
    pub addr: Option<u64>,
    pub closemon: bool,
    pub oep: bool,
    pub hide: bool,
    pub minidump: bool,
    pub out: PathBuf,
}

impl Cli {
    pub fn into_action(self) -> Result<Action> {
        let Cli {
            pid,
            name,
            system,
            addr,
            out,
            closemon,
            db,
            minidump,
            oep,
            launch,
            hide,
            ..
        } = self;

        // -db is a standalone mode; nothing else may ride along.
        if let Some(db) = db {
            if pid.is_some()
                || name.is_some()
                || system
                || addr.is_some()
                || closemon
                || minidump
                || oep
                || launch.is_some()
                || hide
            {
                return Err(RevError::Cli(
                    "-db is a standalone mode and cannot be combined with target or dump options"
                        .into(),
                ));
            }
            return Ok(Action::ManageDb(parse_db(db)?));
        }

        let scope_count = u8::from(pid.is_some())
            + u8::from(name.is_some())
            + u8::from(system)
            + u8::from(launch.is_some());
        if scope_count > 1 {
            return Err(RevError::Cli(
                "choose only one target scope: -pid, -p, -system, or --launch".into(),
            ));
        }

        // -closemon is a modifier on a single PID, not a scope. System-wide termination monitoring
        // would need a kernel callback or injection (both out of scope), so reject every non-pid
        // form here — including bare -closemon — with its own message rather than the generic one.
        if closemon && pid.is_none() {
            return Err(RevError::Cli(
                "-closemon requires -pid (dump a specific process just before it exits); \
                 system-wide monitoring is not supported"
                    .into(),
            ));
        }

        let scope = if let Some(pid) = pid {
            Scope::Pid(pid)
        } else if let Some(regex) = name {
            Scope::NameRegex(regex)
        } else if let Some(path) = launch {
            Scope::Launch(path.to_string_lossy().into_owned())
        } else if system {
            Scope::System
        } else {
            return Err(RevError::Cli(
                "no target: specify -pid, -p, -system, or --launch".into(),
            ));
        };

        if addr.is_some() && !matches!(scope, Scope::Pid(_)) {
            return Err(RevError::Cli("-a requires -pid".into()));
        }
        if addr.is_some() && closemon {
            return Err(RevError::Cli(
                "-a (immediate address dump) cannot be combined with -closemon".into(),
            ));
        }
        if oep {
            if !matches!(scope, Scope::Pid(_) | Scope::Launch(_)) {
                return Err(RevError::Cli("-oep requires -pid or --launch".into()));
            }
            if addr.is_some() || closemon {
                return Err(RevError::Cli(
                    "-oep cannot be combined with -a or -closemon".into(),
                ));
            }
        }
        if hide && !(matches!(scope, Scope::Launch(_)) || addr.is_some() || oep) {
            return Err(RevError::Cli(
                "--hide applies only with --launch, -a, or -oep".into(),
            ));
        }

        Ok(Action::Dump(DumpSpec {
            scope,
            addr,
            closemon,
            oep,
            hide,
            minidump,
            out,
        }))
    }
}

fn parse_db(parts: Vec<String>) -> Result<DbAction> {
    let op = parts.first().map(String::as_str).unwrap_or_default();
    let path = parts.get(1).map(PathBuf::from);
    match op {
        "gen" | "clean" => match path {
            Some(_) => Err(RevError::Cli(format!("-db {op} takes no path argument"))),
            None if op == "gen" => Ok(DbAction::Gen),
            None => Ok(DbAction::Clean),
        },
        "add" => path
            .map(DbAction::Add)
            .ok_or_else(|| RevError::Cli("-db add requires a directory path".into())),
        "rem" => path
            .map(DbAction::Rem)
            .ok_or_else(|| RevError::Cli("-db rem requires a directory path".into())),
        other => Err(RevError::Cli(format!(
            "unknown -db operation '{other}' (expected gen|add|rem|clean)"
        ))),
    }
}

fn parse_u32_auto(s: &str) -> std::result::Result<u32, String> {
    let t = s.trim();
    let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => t.parse::<u32>(),
    };
    parsed.map_err(|e| format!("invalid integer '{s}': {e}"))
}

fn parse_u64_auto(s: &str) -> std::result::Result<u64, String> {
    let t = s.trim();
    let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse::<u64>(),
    };
    parsed.map_err(|e| format!("invalid integer '{s}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Cli {
        Cli {
            pid: None,
            name: None,
            system: false,
            addr: None,
            out: PathBuf::from("."),
            closemon: false,
            db: None,
            minidump: false,
            oep: false,
            launch: None,
            hide: false,
            verbose: 0,
        }
    }

    #[test]
    fn legacy_long_flags_are_rewritten() {
        assert_eq!(remap_legacy_flag("-pid".into()), OsString::from("--pid"));
        assert_eq!(
            remap_legacy_flag("-pid=0x10".into()),
            OsString::from("--pid=0x10")
        );
        assert_eq!(
            remap_legacy_flag("-system".into()),
            OsString::from("--system")
        );
        // genuine short flags and values pass through unchanged
        assert_eq!(remap_legacy_flag("-p".into()), OsString::from("-p"));
        assert_eq!(
            remap_legacy_flag("notepad".into()),
            OsString::from("notepad")
        );
    }

    #[test]
    fn hex_and_decimal_numbers_parse() {
        assert_eq!(parse_u32_auto("0x1F4").unwrap(), 500);
        assert_eq!(parse_u32_auto("500").unwrap(), 500);
        assert_eq!(parse_u64_auto("0xDEADBEEF").unwrap(), 0xDEAD_BEEF);
        assert!(parse_u32_auto("nope").is_err());
    }

    #[test]
    fn two_scopes_conflict() {
        let mut c = base();
        c.pid = Some(1);
        c.system = true;
        assert!(c.into_action().is_err());
    }

    #[test]
    fn no_target_is_rejected() {
        assert!(base().into_action().is_err());
    }

    #[test]
    fn closemon_requires_pid() {
        // Bare -closemon and -closemon -system are rejected: no system-wide monitoring.
        let mut c = base();
        c.closemon = true;
        assert!(c.into_action().is_err());

        let mut c = base();
        c.closemon = true;
        c.system = true;
        assert!(c.into_action().is_err());

        // -closemon -pid X is the one supported form.
        let mut c = base();
        c.closemon = true;
        c.pid = Some(42);
        match c.into_action().unwrap() {
            Action::Dump(spec) => {
                assert!(matches!(spec.scope, Scope::Pid(42)));
                assert!(spec.closemon);
            }
            other => panic!("expected dump, got {other:?}"),
        }
    }

    #[test]
    fn addr_requires_pid() {
        let mut c = base();
        c.system = true;
        c.addr = Some(0x1000);
        assert!(c.into_action().is_err());

        let mut c = base();
        c.pid = Some(42);
        c.addr = Some(0x1000);
        assert!(matches!(c.into_action().unwrap(), Action::Dump(_)));
    }

    #[test]
    fn db_is_exclusive_and_validated() {
        let mut c = base();
        c.db = Some(vec!["gen".into()]);
        c.system = true;
        assert!(
            c.into_action().is_err(),
            "-db must not combine with a scope"
        );

        let mut c = base();
        c.db = Some(vec!["add".into()]);
        assert!(c.into_action().is_err(), "-db add needs a path");

        let mut c = base();
        c.db = Some(vec!["add".into(), "C:/clean".into()]);
        assert!(matches!(
            c.into_action().unwrap(),
            Action::ManageDb(DbAction::Add(_))
        ));
    }
}
