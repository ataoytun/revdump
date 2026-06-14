//! Filtering layer: a clean-hash database to exclude known-good modules, and noise heuristics that
//! drop false-positive code chunks, so only unrecognized code reaches the analyst.

pub mod hashdb;
pub mod noise;
