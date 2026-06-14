//! revdump64: dumps 64-bit targets natively (pd64 model). The arch pairing is build-enforced.

#[cfg(not(target_pointer_width = "64"))]
compile_error!("revdump64 must be built for a 64-bit target (x86_64-pc-windows-msvc)");

fn main() {
    std::process::exit(revdump::run());
}
