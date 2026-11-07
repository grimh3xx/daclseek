//! daclseek — local Windows privilege-escalation misconfiguration enumerator.
//!
//! Read-only security assessment tool: it inspects the host for common local
//! privilege-escalation *misconfigurations* (writable service binaries,
//! unquoted paths, dangerous token privileges, weak UAC/installer policy,
//! exposed credential surfaces) and reports them with remediation guidance.
//! It never exploits, modifies or exfiltrates anything.
//!
//! Intended for authorised security assessments and defensive hardening.

mod checks;
mod report;
mod util;

use report::{Reporter, Severity};

const CHECKS: &[&str] = &[
    "privileges",
    "services",
    "tasks",
    "installer",
    "autoruns",
    "path",
    "uac",
    "credentials",
];

fn print_help() {
    println!(
        "daclseek {} — windows privesc misconfiguration enumerator (read-only)\n",
        env!("CARGO_PKG_VERSION")
    );
    println!("USAGE:");
    println!("    daclseek [OPTIONS]\n");
    println!("OPTIONS:");
    println!("    --json            Emit findings as JSON");
    println!("    --no-color        Disable ANSI colours");
    println!("    --only <check>    Run a single check");
    println!("    --min-severity <s>  Hide findings below <s> (info|low|medium|high|critical)");
    println!("    -h, --help        Show this help");
    println!("    -V, --version     Show version\n");
    println!("EXIT CODE: worst shown finding — 0 none/info, 1 low, 2 medium, 3 high, 4 critical\n");
    println!("CHECKS:");
    println!("    {}", CHECKS.join(", "));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut json = false;
    let mut no_color = false;
    let mut only: Option<String> = None;
    let mut min = Severity::Info;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--no-color" => no_color = true,
            "--only" => {
                i += 1;
                match args.get(i) {
                    Some(v) => only = Some(v.clone()),
                    None => {
                        eprintln!("error: --only requires a check name");
                        std::process::exit(2);
                    }
                }
            }
            "--min-severity" => {
                i += 1;
                match args.get(i).and_then(|v| Severity::parse(v)) {
                    Some(s) => min = s,
                    None => {
                        eprintln!(
                            "error: --min-severity requires info|low|medium|high|critical"
                        );
                        std::process::exit(2);
                    }
                }
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-V" | "--version" => {
                println!("daclseek {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            other => {
                eprintln!("error: unknown argument '{other}'\n");
                print_help();
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if let Some(name) = &only {
        if !CHECKS.contains(&name.as_str()) {
            eprintln!("error: unknown check '{name}' (valid: {})", CHECKS.join(", "));
            std::process::exit(2);
        }
    }

    let ctx = checks::sysinfo::context();
    let mut rep = Reporter::new();
    rep.set_min(min);
    let enabled = |name: &str| only.as_deref().is_none_or(|o| o == name);

    if enabled("privileges") {
        checks::privileges::run(&mut rep);
    }
    if enabled("services") {
        checks::services::run(&mut rep);
    }
    if enabled("tasks") {
        checks::scheduled_tasks::run(&mut rep);
    }
    if enabled("installer") {
        checks::always_install_elevated::run(&mut rep);
    }
    if enabled("autoruns") {
        checks::autoruns::run(&mut rep);
    }
    if enabled("path") {
        checks::path_hijack::run(&mut rep);
    }
    if enabled("uac") {
        checks::uac::run(&mut rep);
    }
    if enabled("credentials") {
        checks::credentials::run(&mut rep);
    }

    if json {
        rep.print_json(&ctx);
    } else {
        rep.print_console(&ctx, !no_color);
    }

    std::process::exit(rep.exit_code());
}
