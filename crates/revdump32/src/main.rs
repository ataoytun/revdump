//! revdump32: dumps 32-bit targets natively (pd32 model). The arch pairing is build-enforced.

#[cfg(not(target_pointer_width = "32"))]
compile_error!("revdump32 must be built for a 32-bit target (i686-pc-windows-msvc)");

fn main() {
    std::process::exit(revdump::run());
}
