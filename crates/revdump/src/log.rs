use std::sync::atomic::{AtomicU8, Ordering};

static VERBOSITY: AtomicU8 = AtomicU8::new(0);

pub fn set_verbosity(level: u8) {
    VERBOSITY.store(level, Ordering::Relaxed);
}

pub fn verbosity() -> u8 {
    VERBOSITY.load(Ordering::Relaxed)
}

/// `vlog!(level, fmt, ...)` — emit to stderr only when `-v` was given at least `level` times.
macro_rules! vlog {
    ($level:expr, $($arg:tt)*) => {{
        if $crate::log::verbosity() >= $level {
            eprintln!($($arg)*);
        }
    }};
}
