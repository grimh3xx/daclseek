//! Service misconfigurations: unquoted paths, writable binaries, writable dirs.
//!
//! Services are read from the registry (no SCM handle needed), so this works
//! from a low-privilege context.

use crate::report::{Reporter, Severity};
use crate::util::{
    can_write, can_write_regkey, parent_dir, parse_exe, reg_get_string, reg_get_u32, reg_subkeys,
    unquoted_candidates, Hive,
};

const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

pub fn run(rep: &mut Reporter) {
    for svc in reg_subkeys(Hive::Hklm, SERVICES) {
        let base = format!("{SERVICES}\\{svc}");

        // Only user-mode Win32 services (own/share process). Skip kernel/fs drivers.
        let svc_type = reg_get_u32(Hive::Hklm, &base, "Type").unwrap_or(0);
        if svc_type & 0x30 == 0 {
            continue;
        }

        // 0. Writable service registry key — lets the user rewrite ImagePath.
        if can_write_regkey(&format!(r"MACHINE\{base}")) {
            rep.push(
                "SVC-004",
                "services",
                &format!("Writable service registry key — '{svc}'"),
                Severity::High,
                "The current user can modify the service's registry configuration, including its ImagePath.",
                vec![format!(r"HKLM\{base}")],
                "Restrict write access on the service key to administrators / SYSTEM.",
            );
        }

        let Some(raw) = reg_get_string(Hive::Hklm, &base, "ImagePath") else {
            continue;
        };

        // 1. Unquoted service path with writable intermediate directory.
        for cand in unquoted_candidates(&raw) {
            if let Some(dir) = parent_dir(&cand) {
                if can_write(&dir) {
                    rep.push(
                        "SVC-001",
                        "services",
                        &format!("Unquoted service path — '{svc}'"),
                        Severity::High,
                        "Unquoted ImagePath with spaces lets a binary dropped at an earlier path segment run as the service account.",
                        vec![
                            format!("ImagePath: {raw}"),
                            format!("hijack binary: {cand}"),
                            format!("writable dir: {dir}"),
                        ],
                        "Quote the ImagePath, or lock down write access to the parent directory.",
                    );
                    break; // one finding per service is enough
                }
            }
        }

        // 2 & 3. Writable service binary / binary directory.
        if let Some(exe) = parse_exe(&raw) {
            if can_write(&exe) {
                rep.push(
                    "SVC-002",
                    "services",
                    &format!("Writable service binary — '{svc}'"),
                    Severity::High,
                    "The current user can overwrite the service executable, which runs as the service account on restart.",
                    vec![format!("binary: {exe}")],
                    "Restrict write access on the binary to administrators / SYSTEM.",
                );
            } else if let Some(dir) = parent_dir(&exe) {
                if can_write(&dir) {
                    rep.push(
                        "SVC-003",
                        "services",
                        &format!("Writable service directory — '{svc}'"),
                        Severity::Medium,
                        "The directory holding the service binary is writable — enables DLL side-loading or binary replacement.",
                        vec![format!("binary: {exe}"), format!("writable dir: {dir}")],
                        "Restrict write access on the service install directory.",
                    );
                }
            }
        }
    }
}
