//! Exposed-credential surfaces.
//!
//! Reports the *presence* of locations that commonly hold plaintext or
//! recoverable secrets. It does not read, decode or exfiltrate secret values —
//! only flags that the exposure exists so it can be remediated.

use crate::report::{Reporter, Severity};
use crate::util::{file_exists, reg_get_string, Hive};

const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

pub fn run(rep: &mut Reporter) {
    // Autologon credentials stored in the registry.
    if reg_get_string(Hive::Hklm, WINLOGON, "DefaultPassword").is_some() {
        let user = reg_get_string(Hive::Hklm, WINLOGON, "DefaultUserName").unwrap_or_default();
        rep.push(
            "CRED-001",
            "credentials",
            "Autologon password present in registry",
            Severity::Critical,
            "A DefaultPassword value is configured for automatic logon and is readable from the registry.",
            vec![
                format!(r"HKLM\{WINLOGON}\DefaultPassword is set"),
                format!("DefaultUserName: {user}"),
            ],
            "Remove the stored password and use the LSA secret-based autologon or disable autologon.",
        );
    }

    // Unattended-install answer files that often retain credentials.
    let unattend = [
        r"C:\Windows\Panther\Unattend.xml",
        r"C:\Windows\Panther\Autounattend.xml",
        r"C:\Windows\System32\Sysprep\Unattend.xml",
        r"C:\Windows\System32\Sysprep\Panther\Unattend.xml",
    ];
    for path in unattend {
        if file_exists(path) {
            rep.push(
                "CRED-002",
                "credentials",
                "Unattend answer file present",
                Severity::High,
                "A sysprep/unattend answer file remains on disk and may contain an embedded account password.",
                vec![format!("file: {path}")],
                "Delete leftover answer files after provisioning; never ship them with secrets.",
            );
        }
    }

    // Backup copies of the security hives.
    let hive_backups = [
        r"C:\Windows\repair\SAM",
        r"C:\Windows\System32\config\RegBack\SAM",
        r"C:\Windows\repair\SYSTEM",
        r"C:\Windows\System32\config\RegBack\SYSTEM",
    ];
    for path in hive_backups {
        if file_exists(path) {
            rep.push(
                "CRED-003",
                "credentials",
                "Security hive backup present",
                Severity::Medium,
                "A backup copy of a security registry hive exists on disk.",
                vec![format!("file: {path}")],
                "Remove stale hive backups and verify their ACLs restrict non-admin read access.",
            );
        }
    }
}
