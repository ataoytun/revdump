//! Access layer: acquire SeDebugPrivilege, open the target (detecting protected processes), and
//! read its memory without aborting on a guarded page.

pub mod open;
pub mod privilege;
pub mod reader;
