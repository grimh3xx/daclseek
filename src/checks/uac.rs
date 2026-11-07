//! UAC configuration review.

use crate::report::{Reporter, Severity};
use crate::util::{reg_get_u32, Hive};

const SYS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

pub fn run(rep: &mut Reporter) {
    let enable_lua = reg_get_u32(Hive::Hklm, SYS, "EnableLUA");
    let consent = reg_get_u32(Hive::Hklm, SYS, "ConsentPromptBehaviorAdmin");
    let secure_desktop = reg_get_u32(Hive::Hklm, SYS, "PromptOnSecureDesktop");

    if enable_lua == Some(0) {
        rep.push(
            "UAC-001",
            "uac",
            "UAC is disabled",
            Severity::High,
            "EnableLUA is 0 — User Account Control is turned off, so admin processes run fully elevated without prompting.",
            vec![format!(r"HKLM\{SYS}\EnableLUA = 0")],
            "Set EnableLUA to 1 and reboot.",
        );
    }

    // 0 = elevate without prompting (least restrictive for admins).
    if consent == Some(0) {
        rep.push(
            "UAC-002",
            "uac",
            "UAC admin consent set to 'elevate without prompting'",
            Severity::Medium,
            "ConsentPromptBehaviorAdmin is 0 — administrators are elevated silently.",
            vec![format!(r"HKLM\{SYS}\ConsentPromptBehaviorAdmin = 0")],
            "Set to 2 (prompt for consent on the secure desktop) or 5 (default).",
        );
    }

    if secure_desktop == Some(0) {
        rep.push(
            "UAC-003",
            "uac",
            "UAC secure desktop disabled",
            Severity::Low,
            "PromptOnSecureDesktop is 0 — consent prompts are shown on the interactive desktop.",
            vec![format!(r"HKLM\{SYS}\PromptOnSecureDesktop = 0")],
            "Set PromptOnSecureDesktop to 1.",
        );
    }
}
