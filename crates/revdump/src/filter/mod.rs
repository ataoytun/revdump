//! Layer 5 — filtering: a clean-hash database to exclude known-good modules, and noise heuristics
//! to drop false-positive code chunks, so only novel code reaches the analyst.

pub mod hashdb;
pub mod noise;
