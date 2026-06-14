# revdump

A user-mode, external reverse-engineering memory dumper for Windows, in the family of
[Process Dump](https://github.com/glmcdona/Process-Dump),
[PE-sieve / HollowsHunter](https://github.com/hasherezade/pe-sieve), and
[Scylla](https://github.com/NtQuad/Scylla).

revdump exists to extract the **original unpacked code** from packed, obfuscated, or hollowed
processes and write it back out as a PE that **loads cleanly into IDA/Ghidra with a sane import
table**. The reconstruction quality is the point — not merely capturing bytes.

> **Status: feature-complete across the planned scope.** All six layers — access, discovery,
> reconstruction, triggers, filtering, output — plus the external-debugger engine and the
> debugger-driven anti-debug layer are implemented and build clean (clippy `-D warnings`, rustfmt)
> on both architectures. It is a working RE tool, not a hardened product: expect rough edges on
> exotic packers. See `crates/revdump/src/` for the module layout.

## What it does

- **Access** — acquire `SeDebugPrivilege`, open targets with NTAPI/Win32 read backends and
  graceful fallback, walk the PEB/LDR manually (packers corrupt the documented loader data), and
  never abort a dump over one guarded/unreadable page.
- **Discovery** — full address-space walk and region classification; PE-signature scanning for
  manually-mapped / reflectively-loaded modules not in the loader list; loose-code-chunk
  detection; in-memory-vs-on-disk diffing to surface inline hooks, header tampering, and process
  hollowing.
- **Reconstruction** — section de-virtualization (memory-aligned by default), PE header repair and
  from-scratch generation for headerless/packer-erased headers, and import-table reconstruction
  (locate IAT, resolve thunks, rebuild the import directory; handle forwarded exports and
  API-redirection stubs).
- **Triggers** — dump on address/breakpoint, on a target API call, on new executable allocation,
  on process termination (`-closemon`), plus a full-system sweep. Launch a target under the
  debugger (`-launch`) so patches land before its first TLS callback, and let the OEP finder
  (`-oep`) catch the jump into unpacked code via a W^X guard flip and dump there.
- **Anti-debug** — at the initial loader breakpoint, neutralize the PEB/heap debugger tells
  (`BeingDebugged`, `NtGlobalFlag`, heap flags) and intercept the debug-detection NTAPI results
  (`NtQueryInformationProcess` debug classes, `NtSetInformationThread(HideFromDebugger)`), all
  driven by breakpoints with no injection (`-hide`).
- **Filtering** — a clean-hash database to exclude known-good modules so only novel code surfaces.
- **Output** — per-region JSON metadata sidecar, parseable filenames, and a separate minidump
  (`.dmp`) export path.

## Build (one binary per architecture)

revdump builds **two arch-locked binaries** so each natively dumps its own bitness, avoiding WOW64
cross-bitness gymnastics (the pd32/pd64 model). Each shim refuses to build for the wrong width.

```sh
# 64-bit dumper (dumps 64-bit targets)
cargo build --release -p revdump64 --target x86_64-pc-windows-msvc   # or: cargo build-64

# 32-bit dumper (dumps 32-bit targets) — requires the 32-bit MSVC linker/toolchain installed
cargo build --release -p revdump32 --target i686-pc-windows-msvc     # or: cargo build-32
```

All shared logic lives in the `revdump` library crate; `revdump32`/`revdump64` are thin shims.
Bare `cargo build`/`cargo clippy` operate on the library only (the bin shims are built per-target
via the aliases in `.cargo/config.toml`).

## Usage (mirrors Process Dump)

```
revdump64 -pid <pid>            dump a process by PID (accepts 0x hex)
revdump64 -p <regex>            dump all processes whose name matches the regex
revdump64 -system               dump all accessible processes
revdump64 -launch <exe>         launch the target under the debugger and dump it
revdump64 -pid <pid> -a <addr>  dump a specific address in the target
revdump64 -oep                  find the original entry point and dump there
revdump64 -hide                 neutralize anti-debug checks while dumping
revdump64 -o <path>             output directory (default: cwd)
revdump64 -closemon -pid <pid>  dump that process at its voluntary exit
revdump64 -db gen|add|rem|clean manage the clean-hash database
revdump64 -minidump             also write a .dmp alongside the PE dumps
revdump64 -v                    verbose (repeatable)
```

The legacy single-dash long flags above and their `--double-dash` equivalents are both accepted.

**Validation:** `-db` is a standalone mode (no target/dump options alongside it); otherwise pick
exactly one scope (`-pid` / `-p` / `-system` / `-launch`). `-closemon` is a modifier on `-pid`
(`-closemon -pid X` dumps X at its voluntary exit); it is not a scope, and system-wide monitoring is
not supported. `-a` requires `-pid`. `-oep` requires `-pid` or `-launch`. `-hide` requires
`-launch`, `-a`, or `-oep` (it needs the debugger engine). Launching the target yourself (`-launch`)
is what lets the anti-debug patches land *before* the first TLS callback; attaching to an
already-running process (`-pid`) only sees its post-startup state.

## Design notes & honest limitations

- **External analysis utility — not an injector.** revdump drives targets as a Win32 debugger
  (breakpoints + `WriteProcessMemory`); it injects no code into the target. It is not a loader,
  packer, or payload mechanism.
- **Memory-aligned dumps by default** (RVA == file offset) so dumps map identically to their
  in-memory layout and load without fixups.
- **One architecture per binary.** `revdump64` dumps 64-bit targets, `revdump32` dumps 32-bit; a
  cross-architecture target (e.g. a 32-bit WOW64 process under `revdump64`) is refused up front
  (and skipped, not dumped, under `-system`/`-p`) — reading its foreign-bitness PEB/LDR would only
  yield import-less, mis-classified output. Run the matching binary.
- **Anti-debug neutralization runs at the initial loader breakpoint.** Under `-launch` that precedes
  the first TLS callback / the entry point — where packers fire their first `IsDebuggerPresent` /
  `NtGlobalFlag` check. On attach (`-oep`/`-a` against a running pid) the breakpoint fires after
  startup, so checks that already ran are not retroactively defeated.
- **Import recovery is direct-pointer.** An IAT slot is resolved by matching the pointer it holds
  against a loaded module's export. IAT entries redirected through a packer's own stub (rather than
  pointing straight at an export) are not resolved, and address-based resolution names the real host
  DLL the export lives in (e.g. `kernelbase`/`ntdll`), not the original `api-ms-win-*` ApiSet /
  forwarder name.
- **OEP detection is single-stage.** It dumps at the first flip-and-execute of freshly-executable
  memory, so a multi-stage or VM-protected packer may stop at an intermediate stage rather than the
  final original entry point.
- **`-closemon` catches voluntary exit only, and requires `-pid`.** It breakpoints the target's own
  `NtTerminateProcess`; an external `TerminateProcess` from another process tears the address space
  down in the kernel first. System-wide monitoring is not supported — reliable external
  termination / new-process notification needs a kernel callback or injection (both out of scope).
- **Native PE only.** A .NET/managed assembly dumps to meaningless native bytes (the real logic is
  JIT-compiled IL) — managed targets are out of scope.
- **Not a commercial-protector unpacker.** TLS-callback handling improves coverage against packers,
  but full defeat of virtualization-based protectors (VMProtect/Themida VM) is a non-goal.
- **No kernel component**, and no attempt to defeat anti-cheat, DRM, HWID, or PPL/protected
  processes — those are detected and reported with a clean message instead.

## License

MIT — see [LICENSE](LICENSE).
