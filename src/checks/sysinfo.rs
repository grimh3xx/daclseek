//! Host context: OS, build, current user, integrity level.

use crate::report::Context;
use crate::util::{integrity_level, reg_get_string, reg_get_u32, Hive};

const CV: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

pub fn context() -> Context {
    let os_name =
        reg_get_string(Hive::Hklm, CV, "ProductName").unwrap_or_else(|| "Windows".to_string());

    let mut build =
        reg_get_string(Hive::Hklm, CV, "CurrentBuild").unwrap_or_else(|| "?".to_string());
    if let Some(ubr) = reg_get_u32(Hive::Hklm, CV, "UBR") {
        build = format!("{build}.{ubr}");
    }

    let display_version = reg_get_string(Hive::Hklm, CV, "DisplayVersion")
        .or_else(|| reg_get_string(Hive::Hklm, CV, "ReleaseId"))
        .unwrap_or_default();

    let arch = std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_else(|_| "unknown".to_string());

    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let name = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());
    let user = if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    };

    Context {
        os_name,
        build,
        display_version,
        arch,
        user,
        integrity: integrity_level(),
    }
}
