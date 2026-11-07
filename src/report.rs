//! Findings model + console / JSON reporting.

use serde::Serialize;

#[derive(Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parse a CLI threshold like `high` or `med`.
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// Process exit code for the worst finding (0 = nothing actionable).
    pub fn exit_code(self) -> i32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED ",
            Severity::Low => "LOW ",
            Severity::Info => "INFO",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Severity::Critical => "\x1b[1;31m",
            Severity::High => "\x1b[31m",
            Severity::Medium => "\x1b[33m",
            Severity::Low => "\x1b[36m",
            Severity::Info => "\x1b[90m",
        }
    }
}

#[derive(Serialize, Clone)]
pub struct Finding {
    pub id: String,
    pub category: String,
    pub title: String,
    pub severity: Severity,
    pub detail: String,
    pub evidence: Vec<String>,
    pub recommendation: String,
}

#[derive(Serialize, Clone)]
pub struct Context {
    pub os_name: String,
    pub build: String,
    pub display_version: String,
    pub arch: String,
    pub user: String,
    pub integrity: String,
}

pub struct Reporter {
    findings: Vec<Finding>,
    min: Severity,
}

impl Reporter {
    pub fn new() -> Self {
        Reporter {
            findings: Vec::new(),
            min: Severity::Info,
        }
    }

    /// Hide findings below this severity from output and exit code.
    pub fn set_min(&mut self, min: Severity) {
        self.min = min;
    }

    /// Exit code derived from the worst *shown* finding.
    pub fn exit_code(&self) -> i32 {
        self.sorted()
            .first()
            .map_or(0, |f| f.severity.exit_code())
    }

    /// Record a finding. `evidence` lines carry the concrete proof.
    #[allow(clippy::too_many_arguments)]
    pub fn push(
        &mut self,
        id: &str,
        category: &str,
        title: &str,
        severity: Severity,
        detail: &str,
        evidence: Vec<String>,
        recommendation: &str,
    ) {
        self.findings.push(Finding {
            id: id.to_string(),
            category: category.to_string(),
            title: title.to_string(),
            severity,
            detail: detail.to_string(),
            evidence,
            recommendation: recommendation.to_string(),
        });
    }

    fn sorted(&self) -> Vec<&Finding> {
        let mut v: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.severity >= self.min)
            .collect();
        // Severity descending, then category for stable grouping.
        v.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.category.cmp(&b.category))
        });
        v
    }

    pub fn print_console(&self, ctx: &Context, color: bool) {
        let (dim, bold, reset) = if color {
            ("\x1b[90m", "\x1b[1m", "\x1b[0m")
        } else {
            ("", "", "")
        };

        println!("{bold}daclseek{reset} {dim}— windows privesc enumeration{reset}");
        println!("{dim}────────────────────────────────────────────────────────{reset}");
        println!("  Host     : {} (build {})", ctx.os_name, ctx.build);
        if !ctx.display_version.is_empty() {
            println!("  Version  : {} ({})", ctx.display_version, ctx.arch);
        } else {
            println!("  Arch     : {}", ctx.arch);
        }
        println!("  User     : {}", ctx.user);
        println!("  Integrity: {}", ctx.integrity);
        println!("{dim}────────────────────────────────────────────────────────{reset}");
        println!();

        let sorted = self.sorted();
        if sorted.is_empty() {
            println!("No misconfigurations found by the enabled checks.");
            return;
        }

        for f in &sorted {
            let (c, reset_c) = if color {
                (f.severity.color(), "\x1b[0m")
            } else {
                ("", "")
            };
            println!(
                "{c}[{}]{reset_c} {dim}({}){reset} {bold}{}{reset}",
                f.severity.label(),
                f.category,
                f.title
            );
            if !f.detail.is_empty() {
                println!("       {}", f.detail);
            }
            for e in &f.evidence {
                println!("       {dim}·{reset} {e}");
            }
            if !f.recommendation.is_empty() {
                println!("       {dim}→ {}{reset}", f.recommendation);
            }
            println!();
        }

        self.print_summary(color);
    }

    fn print_summary(&self, color: bool) {
        use Severity::*;
        let mut counts = [0usize; 5];
        for f in self.findings.iter().filter(|f| f.severity >= self.min) {
            let idx = match f.severity {
                Critical => 0,
                High => 1,
                Medium => 2,
                Low => 3,
                Info => 4,
            };
            counts[idx] += 1;
        }
        let dim = if color { "\x1b[90m" } else { "" };
        let reset = if color { "\x1b[0m" } else { "" };
        println!(
            "{dim}summary:{reset} {} critical · {} high · {} medium · {} low · {} info",
            counts[0], counts[1], counts[2], counts[3], counts[4]
        );
    }

    pub fn print_json(&self, ctx: &Context) {
        let out = serde_json::json!({
            "tool": "daclseek",
            "version": env!("CARGO_PKG_VERSION"),
            "context": ctx,
            "findings": self.sorted(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    }
}
