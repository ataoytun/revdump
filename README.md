# revdump

A user-mode reverse-engineering memory dumper for Windows, in the family of
[Process Dump](https://github.com/glmcdona/Process-Dump),
[PE-sieve / HollowsHunter](https://github.com/hasherezade/pe-sieve), and
[Scylla](https://github.com/ntquery/scylla).

revdump pulls the original unpacked code out of a packed, obfuscated, or hollowed process and writes
it back as a PE that loads into IDA or Ghidra with a usable import table. The value is in the
reconstruction, not the byte capture: it memory-aligns the dump so the file matches the layout the
loader produced, rebuilds an import directory that a packer erased after binding the IAT, and can
capture the image at its original entry point. It is a working tool, not a hardened product; expect
rough edges on exotic packers, and read [Scope and limitations](#scope-and-limitations) before
trusting a result.

## Build

Prerequisites: Rust 1.77 or newer (edition 2021), the MSVC toolchain with both
`x86_64-pc-windows-msvc` and `i686-pc-windows-msvc` targets installed, and Windows 10 or 11. The
tool is Windows-only; it links `windows-sys` plus a hand-rolled NTAPI surface.

revdump ships as two arch-locked binaries built from one workspace. `revdump64` dumps 64-bit targets
and `revdump32` dumps 32-bit targets. Each shim refuses to build for the wrong width, and neither
does WOW64 cross-bitness, so run the binary that matches the target. Build per target:

```sh
# 64-bit dumper
cargo build --release -p revdump64 --target x86_64-pc-windows-msvc   # alias: cargo build-64

# 32-bit dumper (needs the 32-bit MSVC toolchain)
cargo build --release -p revdump32 --target i686-pc-windows-msvc     # alias: cargo build-32
```

All logic lives in the `revdump` library crate; the two binaries are thin shims. The workspace
defaults to the library, so a bare `cargo build` or `cargo clippy` checks the lib only. The
per-target aliases (`build-32`, `build-64`, `check-32`, `check-64`, `clippy-32`, `clippy-64`) are in
`.cargo/config.toml`.

## Usage

Select a target with one scope flag; the trigger and option flags modify it.

| Flag | Argument | Meaning |
|------|----------|---------|
| `-pid` | `<pid>` | Dump a process by PID (decimal or `0x` hex). |
| `-p` | `<regex>` | Dump every accessible process whose image name matches the regex. |
| `-system` | | Dump every accessible process. |
| `-launch` | `<path>` | Launch an executable under the debugger and dump it. |
| `-a` | `<addr>` | Attach, breakpoint that address, dump when execution reaches it (needs `-pid`). |
| `-oep` | | Find the original entry point and dump there (needs `-pid` or `-launch`). |
| `-closemon` | | Dump the target at its voluntary exit (needs `-pid`). |
| `-hide` | | Neutralize common anti-debug checks while dumping (needs `-launch`, `-a`, or `-oep`). |
| `-o` | `<path>` | Output directory (default: current directory). |
| `-minidump` | | Also write a full-memory `.dmp` beside the PE dumps. |
| `--deps` | | Also dump loaded dependency modules (off by default; known-good modules excluded). |
| `-db` | `<op>` | Manage the clean-hash database: `gen`, `add <dir>`, `rem <dir>`, `clean`. |
| `-v` | | Verbose; repeat for more. |

Each long flag accepts both the single-dash form shown above and the `--double-dash` form (`-pid`
and `--pid` are equivalent); `-p`, `-a`, `-o`, and `-v` are genuine short flags, and `--deps` is
double-dash only.

Combinations are validated up front, and an unsupported one is a hard error, not a silent no-op.
`-db` is a standalone mode and takes no target. Pick exactly one scope: `-pid`, `-p`, `-system`, or
`-launch`. `-closemon` is a modifier on `-pid`, not a scope. `-a` requires `-pid`. `-oep` requires
`-pid` or `-launch`. `-hide` needs the debugger engine, so it requires `-launch`, `-a`, or `-oep`.
Launching the target yourself is what lets anti-debug patches land before its first TLS callback;
attaching to a running PID only sees post-startup state.

```sh
# dump a running process by PID
revdump64 -pid 0x1a4

# launch a packed binary under the debugger and dump at the original entry point
revdump64 -launch packed.exe -oep

# launch with anti-debug neutralized, dump at exit
revdump64 -launch packed.exe -hide

# dump every process whose name matches
revdump64 -p "^svchost.*\.exe$"

# sweep all accessible processes into a directory
revdump64 -system -o C:\dumps

# break at an address in a process and dump there
revdump64 -pid 1234 -a 0x7ff61234abcd

# seed the clean-hash database from the system module directories
revdump64 -db gen

# dump a process together with its non-known-good dependency modules
revdump64 -pid 1234 --deps
```

## How it works

The dump runs as a pipeline. Each stage degrades a single bad region rather than aborting the run.

- **Access.** Acquire `SeDebugPrivilege`, open the target, and detect PP/PPL so a protected process
  is reported as protected instead of returning a bare access error. Reads are page-granular: one
  guarded page is zero-filled and recorded, not fatal.
- **Discovery.** Walk the address space with `VirtualQueryEx` and enumerate loaded modules by
  reading the PEB and LDR lists directly, since packers corrupt the documented loader data. The walk
  surfaces what the loader has no record of: manually-mapped or reflectively-loaded images and loose
  executable chunks. A second pass diffs each module's in-memory image against its on-disk file to
  flag inline hooks and hollowing (name, base, header, or entry-point mismatch).
- **Reconstruction.** De-virtualize sections so the file is byte-for-byte the in-memory image
  (RVA == file offset), repair or synthesize headers for headerless or header-erased regions, build
  an address-to-export catalog across the loaded modules (resolving forwarders and ordinal-only
  exports), and rebuild the import directory into an appended `.idata` section whose thunks point
  back at the live IAT, recomputing `SizeOfImage`.
- **Debugger engine.** Triggers and anti-debug are driven by an external Win32 debugger: attach, or
  `CreateProcess` under `DEBUG_PROCESS`, then run the `WaitForDebugEvent` loop with software
  breakpoints (`0xCC`) that re-arm via single-step. No code is injected into the target. The engine
  exposes the initial loader breakpoint, which on a launched target fires before TLS callbacks and
  the entry point, and it tracks TLS callbacks so a pre-EP callback is not mistaken for the OEP.
- **Anti-debug (`-hide`).** At the initial loader breakpoint, normalize the PEB and heap fields a
  packer reads (`BeingDebugged`, `NtGlobalFlag`, heap flags) and rewrite the debug-detection syscall
  results by breakpointing their returns: the `NtQueryInformationProcess` debug classes and
  `NtSetInformationThread(ThreadHideFromDebugger)`. Breakpoints and memory writes only, no injection.
- **OEP capture (`-oep`).** Watch `NtProtectVirtualMemory` for a transition to executable, strip
  execute from that region, and let the packer's jump into the unpacked code fault on DEP. The fault
  address is the original entry point; revdump restores protection, dumps, and writes the recovered
  OEP into the dumped header.
- **Filtering.** A clean-hash database (SHA-256 of on-disk system modules) excludes known-good code
  so only unrecognized regions surface, and a noise heuristic drops loose chunks that reference no
  real imports.

## Scope and limitations

These are deliberate boundaries, stated plainly.

- **One architecture per binary.** `revdump64` dumps 64-bit targets, `revdump32` dumps 32-bit. A
  cross-architecture target (for example a 32-bit WOW64 process under `revdump64`) is refused up
  front, and skipped rather than dumped under `-system` and `-p`. Reading a foreign-bitness PEB/LDR
  would only yield import-less, mis-classified output. Run the matching binary.
- **Native PE only.** A .NET or other managed assembly dumps to meaningless native bytes; its real
  logic is JIT-compiled IL that is not present in the native image.
- **Single-stage OEP.** The finder dumps at the first flip-and-execute of freshly-executable memory.
  A multi-stage or VM-protected packer may stop at an intermediate stage rather than the final entry
  point.
- **Direct-pointer imports.** An IAT slot is resolved by matching the pointer it holds against a
  loaded module's export. Slots redirected through a packer's own stub (rather than pointing at an
  export) are not resolved, and address-based resolution names the real host DLL the export lives in
  (such as `kernelbase` or `ntdll`), not the original `api-ms-win-*` ApiSet or forwarder name.
- **`-closemon` is voluntary-exit only.** It breakpoints the target's own `NtTerminateProcess`. An
  external `TerminateProcess` from another process tears the address space down in the kernel first
  and cannot be caught. System-wide termination monitoring would need a kernel callback or injection,
  so `-closemon` requires `-pid`.
- **Anti-debug timing depends on how you reach the target.** Patches land before the first TLS
  callback only under `-launch`. On attach (`-oep` or `-a` against a running PID) the initial
  breakpoint fires after startup, so a check that already ran is not retroactively defeated.
- **Not a commercial-protector unpacker.** TLS-callback tracking improves coverage, but defeating
  virtualization-based protectors (VMProtect, Themida) is a non-goal.
- **No kernel component, and no protection bypass.** revdump is user-mode only and makes no attempt
  to defeat anti-cheat, DRM, HWID checks, or PPL. Protected targets are detected and reported.

## Output

Each run writes one directory under `-o` (default current directory), named
`<image>_<pid>_<YYYYMMDD-HHMMSS>` (local time; the pid keeps it unique under `-system`/`-p`). Inside:

- `main/` the reconstructed main image.
- `modules/` hidden, manually-mapped, or reflectively-loaded PEs.
- `chunks/` headerless loose code.
- `deps/` loaded dependency modules, only with `--deps`.
- `manifest.json` at the run-dir root, a sidecar describing the run. Each artifact records its file,
  kind, base and real base, size, unreadable-page count, header origin (original or synthesized),
  import state (original, reconstructed, or none), a confidence label, and the detected `oep` when
  dumped via `-oep`. Skipped or failed regions are listed under `notes` with a reason.
- `<pid>.dmp` at the root, a full-memory minidump, only with `-minidump`.

A subdirectory appears only when it has content. Dependency modules are not dumped by default
(known-good library code is better read from its on-disk file); `--deps` captures them, excluding any
module whose on-disk file matches the clean-hash database.

Artifact filenames are parseable: `pid_base_arch_kind[_hollow].ext`, where `arch` is `x64` or `x86`,
`kind` is `main`, `hidden`, `chunk`, or `dep`, the `_hollow` tag marks a hollowed main image, and the
extension is `exe` for images, `dll` for dependencies, or `bin` for raw chunks. For example,
`main/1a4_7ff6a8530000_x64_main.exe`.

## Use

revdump is an external analysis tool for software you have the right to reverse-engineer: your own
binaries, malware in a controlled lab, or work you are authorized to perform.

## License

MIT. See [LICENSE](LICENSE).
