//! AlwaysInstallElevated policy detection.
//!
//! When this policy value is enabled in both the machine and user hives, the
//! Windows Installer service applies installer packages with elevated rights
//! for standard users. It is a well-known hardening misconfiguration; this
//! check only reports its state.

use crate::report::{Reporter, Severity};
use crate::util::{reg_get_u32, Hive};

const KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\Installer";

pub fn run(rep: &mut Reporter) {
    let hklm = reg_get_u32(Hive::Hklm, KEY, "AlwaysInstallElevated").unwrap_or(0);
    let hkcu = reg_get_u32(Hive::Hkcu, KEY, "AlwaysInstallElevated").unwrap_or(0);

    if hklm == 1 && hkcu == 1 {
        rep.push(
            "AIE-001",
            "policy",
            "AlwaysInstallElevated enabled (HKLM + HKCU)",
            Severity::Critical,
            "Installer packages are applied with elevated privileges for standard users.",
            vec![
                format!(r"HKLM\{KEY}\AlwaysInstallElevated = 1"),
                format!(r"HKCU\{KEY}\AlwaysInstallElevated = 1"),
            ],
            "Set both values to 0 (or remove the policy) via GPO: Administrative Templates > Windows Installer.",
        );
    } else if hklm == 1 || hkcu == 1 {
        rep.push(
            "AIE-002",
            "policy",
            "AlwaysInstallElevated set in one hive only",
            Severity::Info,
            "The policy is only effective when enabled in both hives, but a half-set value is worth cleaning up.",
            vec![format!("HKLM={hklm}, HKCU={hkcu}")],
            "Set the value to 0 in the hive where it is present.",
        );
    }
}
