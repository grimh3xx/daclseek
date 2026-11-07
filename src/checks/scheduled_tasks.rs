//! Scheduled tasks whose action binary (or its directory) is writable by the
//! current user. A task defined to run as a higher-privileged principal with a
//! user-writable binary is a straightforward escalation exposure.
//!
//! Task definitions are read from their on-disk XML under System32\Tasks, so no
//! Task Scheduler COM interface is required.

use std::path::{Path, PathBuf};

use crate::report::{Reporter, Severity};
use crate::util::{can_write, expand_path, parent_dir, parse_exe};

pub fn run(rep: &mut Reporter) {
    let windir = std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| "C:\\Windows".to_string());
    let root = PathBuf::from(windir).join("System32").join("Tasks");

    let mut files = Vec::new();
    collect_files(&root, &mut files, 0);

    for file in files {
        let Some(xml) = read_task_xml(&file) else {
            continue;
        };
        let Some(cmd) = extract_tag(&xml, "Command") else {
            continue;
        };
        let Some(exe) = parse_exe(&expand_path(&cmd)) else {
            continue;
        };

        let task_name = file
            .strip_prefix(&root)
            .ok()
            .and_then(|p| p.to_str())
            .map(|s| s.replace('\\', "/"))
            .unwrap_or_else(|| file.display().to_string());

        if can_write(&exe) {
            rep.push(
                "TASK-001",
                "scheduled-tasks",
                &format!("Writable scheduled-task binary — '{task_name}'"),
                Severity::High,
                "The executable launched by a scheduled task is writable by the current user.",
                vec![format!("task: {task_name}"), format!("binary: {exe}")],
                "Restrict write access on the task binary to administrators / SYSTEM.",
            );
        } else if let Some(dir) = parent_dir(&exe) {
            if can_write(&dir) {
                rep.push(
                    "TASK-002",
                    "scheduled-tasks",
                    &format!("Writable scheduled-task directory — '{task_name}'"),
                    Severity::Medium,
                    "The directory of a scheduled-task binary is writable (side-loading exposure).",
                    vec![format!("binary: {exe}"), format!("writable dir: {dir}")],
                    "Restrict write access on the task binary's directory.",
                );
            }
        }
    }
}

/// Recurse the Tasks tree (bounded depth), collecting regular files.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => collect_files(&path, out, depth + 1),
            Ok(ft) if ft.is_file() => out.push(path),
            _ => {}
        }
    }
}

/// Task XML is typically UTF-16LE with a BOM; fall back to UTF-8.
fn read_task_xml(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let (pairs, _) = bytes[2..].as_chunks::<2>();
        let u16s: Vec<u16> = pairs.iter().map(|&[a, b]| u16::from_le_bytes([a, b])).collect();
        Some(String::from_utf16_lossy(&u16s))
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// Extract the text content of the first `<tag>...</tag>` (namespace-agnostic).
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let text = xml[start..end].trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}
