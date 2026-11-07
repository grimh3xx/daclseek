//! Dangerous token privileges held by the current process.
//!
//! Holding a privilege is what matters — a disabled privilege the token still
//! *holds* can usually be enabled by the process itself, so both are reported.

use crate::report::{Reporter, Severity};
use crate::util::token_privileges;

/// (privilege, severity, note)
const DANGEROUS: &[(&str, Severity, &str)] = &[
    (
        "SeImpersonatePrivilege",
        Severity::High,
        "Impersonate a client after authentication — classic Potato-family SYSTEM escalation.",
    ),
    (
        "SeAssignPrimaryTokenPrivilege",
        Severity::High,
        "Assign a primary token to a new process — combine with a captured SYSTEM token.",
    ),
    (
        "SeDebugPrivilege",
        Severity::High,
        "Open and inject into any process, including SYSTEM-owned ones.",
    ),
    (
        "SeTcbPrivilege",
        Severity::Critical,
        "Act as part of the OS — effectively full compromise.",
    ),
    (
        "SeCreateTokenPrivilege",
        Severity::Critical,
        "Forge an arbitrary access token, including one for SYSTEM.",
    ),
    (
        "SeLoadDriverPrivilege",
        Severity::High,
        "Load a kernel driver — BYOVD / kernel code execution path.",
    ),
    (
        "SeBackupPrivilege",
        Severity::High,
        "Read any file regardless of DACL — dump SAM/SYSTEM hives for secrets.",
    ),
    (
        "SeRestorePrivilege",
        Severity::High,
        "Write any file/registry key regardless of DACL — overwrite a service binary.",
    ),
    (
        "SeTakeOwnershipPrivilege",
        Severity::High,
        "Take ownership of any securable object, then rewrite its DACL.",
    ),
    (
        "SeManageVolumePrivilege",
        Severity::Medium,
        "Low-level volume access that can be abused to gain write to protected files.",
    ),
];

pub fn run(rep: &mut Reporter) {
    let held = token_privileges();
    if held.is_empty() {
        return;
    }

    for (name, enabled) in &held {
        if let Some((_, sev, note)) = DANGEROUS.iter().find(|(p, _, _)| p == name) {
            let state = if *enabled { "enabled" } else { "disabled (but held)" };
            rep.push(
                "PRIV-001",
                "privileges",
                name,
                *sev,
                note,
                vec![format!("token holds {name} — {state}")],
                "Remove this privilege from accounts that don't strictly need it.",
            );
        }
    }
}
