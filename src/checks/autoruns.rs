//! Autorun entries (Run keys) whose target binary or directory is writable by
//! the current user — a persistence/escalation exposure if the entry runs in a
//! higher-privileged context.

use crate::report::{Reporter, Severity};
use crate::util::{can_write, parent_dir, parse_exe, reg_get_string, reg_value_names, Hive};

const RUN_KEYS: &[(Hive, &str)] = &[
    (Hive::Hklm, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    (Hive::Hkcu, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
];

pub fn run(rep: &mut Reporter) {
    for (hive, key) in RUN_KEYS {
        for name in reg_value_names(*hive, key) {
            let Some(raw) = reg_get_string(*hive, key, &name) else {
                continue;
            };
            let Some(exe) = parse_exe(&raw) else { continue };

            let hive_name = match hive {
                Hive::Hklm => "HKLM",
                Hive::Hkcu => "HKCU",
            };

            if can_write(&exe) {
                rep.push(
                    "RUN-001",
                    "autoruns",
                    &format!("Writable autorun binary — '{name}'"),
                    Severity::High,
                    "An autorun target executable is writable by the current user.",
                    vec![
                        format!(r"{hive_name}\{key}\{name}"),
                        format!("binary: {exe}"),
                    ],
                    "Restrict write access to the autorun binary.",
                );
            } else if let Some(dir) = parent_dir(&exe) {
                if can_write(&dir) {
                    rep.push(
                        "RUN-002",
                        "autoruns",
                        &format!("Writable autorun directory — '{name}'"),
                        Severity::Medium,
                        "The directory of an autorun target is writable (side-loading exposure).",
                        vec![format!("binary: {exe}"), format!("writable dir: {dir}")],
                        "Restrict write access to the autorun directory.",
                    );
                }
            }
        }
    }
}
