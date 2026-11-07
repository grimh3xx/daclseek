//! Writable directories on the system PATH.
//!
//! A user-writable directory listed on PATH is a search-order exposure for any
//! process that resolves an executable or library by name.

use crate::report::{Reporter, Severity};
use crate::util::can_write;

pub fn run(rep: &mut Reporter) {
    let Ok(path) = std::env::var("PATH") else {
        return;
    };

    for dir in path.split(';') {
        let dir = dir.trim();
        if dir.is_empty() {
            continue;
        }
        if can_write(dir) {
            rep.push(
                "PATH-001",
                "path",
                "Writable directory on PATH",
                Severity::High,
                "A directory on the system PATH is writable by the current user, which exposes name-based executable/library resolution.",
                vec![format!("writable PATH entry: {dir}")],
                "Remove the entry from PATH or restrict its write permissions.",
            );
        }
    }
}
