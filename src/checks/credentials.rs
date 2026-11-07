//! Exposed-credential surfaces.
//!
//! Reports the *presence* of locations that commonly hold plaintext or
//! recoverable secrets. It does not read, decode or exfiltrate secret values —
//! only flags that the exposure exists so it can be remediated. The one
//! exception is GPP `cpassword`, which is encrypted with a *publicly known* AES
//! key, so its mere presence is itself the finding.

use std::path::{Path, PathBuf};

use crate::report::{Reporter, Severity};
use crate::util::{file_exists, reg_get_string, reg_subkeys, reg_value_names, Hive};

const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

pub fn run(rep: &mut Reporter) {
    autologon(rep);
    answer_files(rep);
    hive_backups(rep);
    putty(rep);
    winscp(rep);
    vnc(rep);
    ssh_keys(rep);
    shell_history(rep);
    cloud_creds(rep);
    gpp_cpassword(rep);
}

fn autologon(rep: &mut Reporter) {
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
            "Remove the stored password; use LSA-secret autologon or disable it.",
        );
    }
}

fn answer_files(rep: &mut Reporter) {
    let paths = [
        r"C:\Windows\Panther\Unattend.xml",
        r"C:\Windows\Panther\Autounattend.xml",
        r"C:\Windows\System32\Sysprep\Unattend.xml",
        r"C:\Windows\System32\Sysprep\Panther\Unattend.xml",
    ];
    for path in paths {
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
}

fn hive_backups(rep: &mut Reporter) {
    let paths = [
        r"C:\Windows\repair\SAM",
        r"C:\Windows\System32\config\RegBack\SAM",
        r"C:\Windows\repair\SYSTEM",
        r"C:\Windows\System32\config\RegBack\SYSTEM",
    ];
    for path in paths {
        if file_exists(path) {
            rep.push(
                "CRED-003",
                "credentials",
                "Security hive backup present",
                Severity::Medium,
                "A backup copy of a security registry hive exists on disk.",
                vec![format!("file: {path}")],
                "Remove stale hive backups and verify their ACLs restrict non-admin read.",
            );
        }
    }
}

fn putty(rep: &mut Reporter) {
    let root = r"SOFTWARE\SimonTatham\PuTTY\Sessions";
    for session in reg_subkeys(Hive::Hkcu, root) {
        let sk = format!("{root}\\{session}");
        if reg_get_string(Hive::Hkcu, &sk, "ProxyPassword").is_some() {
            let host = reg_get_string(Hive::Hkcu, &sk, "HostName").unwrap_or_default();
            rep.push(
                "CRED-004",
                "credentials",
                &format!("PuTTY proxy password stored — '{session}'"),
                Severity::High,
                "PuTTY stores the proxy password in cleartext in the registry.",
                vec![
                    format!(r"HKCU\{sk}\ProxyPassword"),
                    format!("host: {host}"),
                ],
                "Clear the saved proxy password from the PuTTY session.",
            );
        }
    }
}

fn winscp(rep: &mut Reporter) {
    let root = r"SOFTWARE\Martin Prikryl\WinSCP 2\Sessions";
    let master = reg_get_string(Hive::Hkcu, r"SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security", "UseMasterPassword");
    let master_on = master.as_deref() == Some("1");
    for session in reg_subkeys(Hive::Hkcu, root) {
        let sk = format!("{root}\\{session}");
        if reg_value_names(Hive::Hkcu, &sk).iter().any(|v| v == "Password") {
            let host = reg_get_string(Hive::Hkcu, &sk, "HostName").unwrap_or_default();
            rep.push(
                "CRED-005",
                "credentials",
                &format!("WinSCP session password stored — '{session}'"),
                if master_on { Severity::Medium } else { Severity::High },
                "WinSCP stores the session password with reversible obfuscation (recoverable without a master password).",
                vec![
                    format!(r"HKCU\{sk}\Password"),
                    format!("host: {host}"),
                    format!("master password: {}", if master_on { "enabled" } else { "disabled" }),
                ],
                "Enable a WinSCP master password or avoid saving session passwords.",
            );
        }
    }
}

fn vnc(rep: &mut Reporter) {
    // (hive, key, value, product)
    let targets: &[(Hive, &str, &str, &str)] = &[
        (Hive::Hklm, r"SOFTWARE\TightVNC\Server", "Password", "TightVNC"),
        (Hive::Hklm, r"SOFTWARE\TightVNC\Server", "PasswordViewOnly", "TightVNC"),
        (Hive::Hklm, r"SOFTWARE\RealVNC\vncserver", "Password", "RealVNC"),
        (Hive::Hkcu, r"SOFTWARE\ORL\WinVNC3", "Password", "WinVNC"),
    ];
    for (hive, key, value, product) in targets {
        if reg_value_names(*hive, key).iter().any(|v| v == value) {
            rep.push(
                "CRED-006",
                "credentials",
                &format!("{product} password stored in registry"),
                Severity::High,
                "VNC stores its password with a fixed, publicly known DES key — trivially recoverable.",
                vec![format!(r"{}\{key}\{value}", hive_label(*hive))],
                "Rotate to a product that stores credentials securely, or restrict read access to the key.",
            );
        }
    }
    if file_exists(r"C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini") {
        rep.push(
            "CRED-006",
            "credentials",
            "UltraVNC configuration present",
            Severity::Medium,
            "ultravnc.ini commonly stores an obfuscated password.",
            vec![r"file: C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini".to_string()],
            "Restrict read access to ultravnc.ini.",
        );
    }
}

fn ssh_keys(rep: &mut Reporter) {
    let Ok(profile) = std::env::var("USERPROFILE") else {
        return;
    };
    for name in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"] {
        let path = format!(r"{profile}\.ssh\{name}");
        if file_exists(&path) {
            rep.push(
                "CRED-007",
                "credentials",
                &format!("OpenSSH private key present — {name}"),
                Severity::Medium,
                "An SSH private key is stored in the user profile.",
                vec![format!("file: {path}")],
                "Ensure the key is passphrase-protected and its ACL restricts access to the owner.",
            );
        }
    }
}

fn shell_history(rep: &mut Reporter) {
    let Ok(appdata) = std::env::var("APPDATA") else {
        return;
    };
    let path = format!(r"{appdata}\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
    if file_exists(&path) {
        rep.push(
            "CRED-008",
            "credentials",
            "PowerShell command history present",
            Severity::Low,
            "PSReadLine history often captures secrets passed on the command line.",
            vec![format!("file: {path}")],
            "Review and clear the history; avoid passing secrets as plaintext arguments.",
        );
    }
}

fn cloud_creds(rep: &mut Reporter) {
    let Ok(profile) = std::env::var("USERPROFILE") else {
        return;
    };
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let candidates = [
        (format!(r"{profile}\.aws\credentials"), "AWS"),
        (format!(r"{profile}\.azure\accessTokens.json"), "Azure"),
        (format!(r"{appdata}\gcloud\credentials.db"), "gcloud"),
        (format!(r"{profile}\.config\gcloud\credentials.db"), "gcloud"),
    ];
    for (path, product) in candidates {
        if !path.contains("\\\\") && file_exists(&path) {
            rep.push(
                "CRED-009",
                "credentials",
                &format!("{product} credentials file present"),
                Severity::Medium,
                "A cloud SDK credentials/token file is stored in the user profile.",
                vec![format!("file: {path}")],
                "Ensure the file's ACL restricts access and prefer short-lived / SSO credentials.",
            );
        }
    }
}

/// Group Policy Preferences `cpassword` — AES-encrypted with a key Microsoft
/// published, so any cpassword value is effectively plaintext.
fn gpp_cpassword(rep: &mut Reporter) {
    let Ok(pd) = std::env::var("ProgramData") else {
        return;
    };
    let root = PathBuf::from(pd).join(r"Microsoft\Group Policy\History");
    let mut xmls = Vec::new();
    collect_xml(&root, &mut xmls, 0);
    for path in xmls {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(idx) = text.find("cpassword=\"") {
            let val = &text[idx + 11..];
            if val.starts_with('"') {
                continue; // empty cpassword=""
            }
            rep.push(
                "CRED-010",
                "credentials",
                "Group Policy Preferences cpassword found",
                Severity::Critical,
                "A GPP cpassword is encrypted with a publicly known AES key and is recoverable to plaintext.",
                vec![format!("file: {}", path.display())],
                "Remove the GPP item defining the credential; rotate the exposed account.",
            );
        }
    }
}

fn collect_xml(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 10 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => collect_xml(&path, out, depth + 1),
            Ok(ft)
                if ft.is_file()
                    && path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.eq_ignore_ascii_case("xml"))
                        .unwrap_or(false) =>
            {
                out.push(path)
            }
            _ => {}
        }
    }
}

fn hive_label(h: Hive) -> &'static str {
    match h {
        Hive::Hklm => "HKLM",
        Hive::Hkcu => "HKCU",
    }
}
