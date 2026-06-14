# revdump

A user-mode, external reverse-engineering memory dumper for Windows, in the family of
[Process Dump](https://github.com/glmcdona/Process-Dump),
[PE-sieve / HollowsHunter](https://github.com/hasherezade/pe-sieve), and
[Scylla](https://github.com/NtQuad/Scylla).

revdump exists to extract the **original unpacked code** from packed, obfuscated, or hollowed
processes and write it back out as a PE that **loads cleanly into IDA/Ghidra with a sane import
table**. The reconstruction quality is the point — not merely capturing bytes.

> **Status: early development.** The architecture, CLI surface, and build are in place; the
> dumping layers are landing milestone by milestone. See `crates/revdump/src/` for current scope.

## What it does (target scope)

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
  on process termination (`-closemon`), plus a full-system sweep, with OEP-detection heuristics.
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
revdump64 -pid <pid> -a <addr>  dump a specific address in the target
revdump64 -o <path>             output directory (default: cwd)
revdump64 -closemon [scope]     dump processes just before they exit
revdump64 -db gen|add|rem|clean manage the clean-hash database
revdump64 -minidump             also write a .dmp alongside the PE dumps
revdump64 -v                    verbose (repeatable)
```

The legacy single-dash long flags above and their `--double-dash` equivalents are both accepted.

**Validation:** `-db` is a standalone mode (no target/dump options alongside it); otherwise pick
exactly one scope (`-pid` / `-p` / `-system`). `-closemon` is a mode modifier that combines with a
scope (`-closemon -pid X` dumps X just before it exits); bare `-closemon` means system-wide
best-effort monitoring. `-a` requires `-pid`.

## Design notes & honest limitations

- **External analysis utility — not an injector.** revdump drives targets as a Win32 debugger
  (breakpoints + `WriteProcessMemory`); it injects no code into the target. It is not a loader,
  packer, or payload mechanism.
- **Memory-aligned dumps by default** (RVA == file offset) so dumps map identically to their
  in-memory layout and load without fixups.
- **Anti-debug neutralization runs at the initial loader breakpoint** — before the first TLS
  callback or entry-point code — because that is where packers fire their first
  `IsDebuggerPresent` / `NtGlobalFlag` check.
- **`-closemon` is best-effort system-wide.** Reliable for processes revdump launches/attaches to;
  catching unrelated, brand-new short-lived processes is inherently racy without a kernel callback
  or injection (both out of scope).
- **Native PE only.** A .NET/managed assembly dumps to meaningless native bytes (the real logic is
  JIT-compiled IL) — managed targets are out of scope.
- **Not a commercial-protector unpacker.** TLS-callback handling improves coverage against packers,
  but full defeat of virtualization-based protectors (VMProtect/Themida VM) is a non-goal.
- **No kernel component**, and no attempt to defeat anti-cheat, DRM, HWID, or PPL/protected
  processes — those are detected and reported with a clean message instead.

## License

MIT — see [LICENSE](LICENSE).
