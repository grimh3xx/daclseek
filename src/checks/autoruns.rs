//! Autostart extension points whose target is writable by the current user, or
//! whose mere presence is a persistence/hijack signal:
//!
//! * `Run` / `RunOnce` entries with a writable target binary or directory
//! * Winlogon `Shell` / `Userinit` pointing at a writable binary
//! * `AppInit_DLLs` (when enabled) with a writable DLL
//! * Image File Execution Options `Debugger` values
//! * writable per-machine / per-user Startup folders

use crate::report::{Reporter, Severity};
use crate::util::{
    can_write, expand_path, parent_dir, parse_exe, reg_get_string, reg_get_u32, reg_subkeys,
    reg_value_names, Hive,
};

const RUN_KEYS: &[(Hive, &str)] = &[
    (Hive::Hklm, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    (Hive::Hkcu, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
];

const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
const WINDOWS: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
const IFEO: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

pub fn run(rep: &mut Reporter) {
    run_keys(rep);
    logon_hooks(rep);
    appinit_dlls(rep);
    ifeo_debuggers(rep);
    startup_folders(rep);
}

fn run_keys(rep: &mut Reporter) {
    for (hive, key) in RUN_KEYS {
        for name in reg_value_names(*hive, key) {
            let Some(raw) = reg_get_string(*hive, key, &name) else {
                continue;
            };
            let Some(exe) = parse_exe(&raw) else { continue };
            let hive_name = hive_label(*hive);

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

fn logon_hooks(rep: &mut Reporter) {
    // Winlogon Shell and Userinit can each be a comma-separated list.
    for value in ["Shell", "Userinit"] {
        let Some(raw) = reg_get_string(Hive::Hklm, WINLOGON, value) else {
            continue;
        };
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some(exe) = parse_exe(part) else { continue };
            if can_write(&exe) {
                rep.push(
                    "RUN-003",
                    "autoruns",
                    &format!("Writable Winlogon {value} target"),
                    Severity::High,
                    "A Winlogon logon hook points at a binary writable by the current user.",
                    vec![format!(r"HKLM\{WINLOGON}\{value}"), format!("binary: {exe}")],
                    "Restore the default value and restrict write access to the target.",
                );
            }
        }
    }
}

fn appinit_dlls(rep: &mut Reporter) {
    let wow = r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows";
    for key in [WINDOWS, wow] {
        if reg_get_u32(Hive::Hklm, key, "LoadAppInit_DLLs") != Some(1) {
            continue;
        }
        let Some(raw) = reg_get_string(Hive::Hklm, key, "AppInit_DLLs") else {
            continue;
        };
        if raw.trim().is_empty() {
            continue;
        }
        for dll in raw.split([',', ' ']) {
            let dll = dll.trim();
            if dll.is_empty() {
                continue;
            }
            let dll = expand_path(dll);
            let writable = can_write(&dll);
            rep.push(
                "RUN-004",
                "autoruns",
                "AppInit_DLLs enabled",
                if writable { Severity::High } else { Severity::Medium },
                "AppInit_DLLs is active — these DLLs load into most user-mode processes.",
                vec![
                    format!(r"HKLM\{key}\AppInit_DLLs"),
                    format!("dll: {dll}{}", if writable { "  (writable!)" } else { "" }),
                ],
                "Disable LoadAppInit_DLLs and clear AppInit_DLLs unless explicitly required.",
            );
        }
    }
}

fn ifeo_debuggers(rep: &mut Reporter) {
    for image in reg_subkeys(Hive::Hklm, IFEO) {
        let subkey = format!("{IFEO}\\{image}");
        let Some(dbg) = reg_get_string(Hive::Hklm, &subkey, "Debugger") else {
            continue;
        };
        let exe = parse_exe(&dbg);
        let writable = exe.as_deref().map(can_write).unwrap_or(false);
        rep.push(
            "RUN-005",
            "autoruns",
            &format!("IFEO debugger set for '{image}'"),
            if writable { Severity::High } else { Severity::Medium },
            "An Image File Execution Options debugger launches in place of the target image — a classic hijack/persistence hook.",
            vec![
                format!(r"HKLM\{subkey}\Debugger"),
                format!("debugger: {dbg}"),
            ],
            "Remove the Debugger value unless it is a known, intentional configuration.",
        );
    }
}

fn startup_folders(rep: &mut Reporter) {
    let mut dirs = Vec::new();
    if let Ok(pd) = std::env::var("ProgramData") {
        dirs.push((
            format!(r"{pd}\Microsoft\Windows\Start Menu\Programs\StartUp"),
            "all-users",
        ));
    }
    if let Ok(ad) = std::env::var("APPDATA") {
        dirs.push((
            format!(r"{ad}\Microsoft\Windows\Start Menu\Programs\Startup"),
            "per-user",
        ));
    }
    for (dir, scope) in dirs {
        if can_write(&dir) {
            rep.push(
                "RUN-006",
                "autoruns",
                &format!("Writable {scope} Startup folder"),
                Severity::Medium,
                "A Startup folder is writable — anything dropped there runs at logon.",
                vec![format!("writable dir: {dir}")],
                "Restrict write access on the Startup folder to its intended principals.",
            );
        }
    }
}

fn hive_label(h: Hive) -> &'static str {
    match h {
        Hive::Hklm => "HKLM",
        Hive::Hkcu => "HKCU",
    }
}
