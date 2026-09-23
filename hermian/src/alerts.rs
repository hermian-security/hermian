//! `hermian alerts` and `hermian show`: read alerts back from the JSON store.

use std::fs;

use anyhow::{Context, Result};
use chrono::Utc;
use hermian_core::{render, Alert, DetectionId};

use crate::cli::{severity_filter, AlertsArgs, ShowArgs};
use crate::paths;
use crate::ui::{ago, Style};

/// Alerts are root-only; say so rather than "no alerts" or "no such alert".
fn needs_root(e: &std::io::Error) -> Option<anyhow::Error> {
    (e.kind() == std::io::ErrorKind::PermissionDenied)
        .then(|| anyhow::anyhow!("alerts are root-only; re-run with sudo"))
}

fn load_all() -> Result<Vec<Alert>> {
    let dir = paths::alerts_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            if let Some(err) = needs_root(&e) {
                return Err(err);
            }
            return Ok(Vec::new());
        }
    };
    let mut alerts: Vec<Alert> = entries
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .filter_map(|t| serde_json::from_str::<Alert>(&t).ok())
        // Files written before escaping existed may hold raw control chars.
        .map(Alert::sanitized)
        .collect();
    // Newest first; the ref id is a monotonic per-day sequence so it breaks
    // ties between alerts raised in the same instant.
    alerts.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.ref_id.cmp(&a.ref_id)));
    Ok(alerts)
}

fn parse_detection(s: &str) -> Option<DetectionId> {
    match s.to_ascii_uppercase().as_str() {
        "D1" => Some(DetectionId::D1),
        "D2" => Some(DetectionId::D2),
        "D3" => Some(DetectionId::D3),
        "D4" => Some(DetectionId::D4),
        "D5" => Some(DetectionId::D5),
        "SELF" => Some(DetectionId::Self_),
        _ => None,
    }
}

pub fn cmd_alerts(args: &AlertsArgs) -> Result<()> {
    let st = Style::detect();
    let min = severity_filter(args.severity.as_deref())?;
    let det = match &args.detection {
        Some(d) => {
            Some(parse_detection(d).ok_or_else(|| anyhow::anyhow!("unknown detection '{}'", d))?)
        }
        None => None,
    };
    let alerts: Vec<Alert> = load_all()?
        .into_iter()
        .filter(|a| min.map(|m| a.severity >= m).unwrap_or(true))
        .filter(|a| det.map(|d| a.detection == d).unwrap_or(true))
        .take(args.limit.max(1))
        .collect();

    if args.json {
        for a in &alerts {
            println!("{}", serde_json::to_string(a)?);
        }
        return Ok(());
    }

    if alerts.is_empty() {
        println!("{}", st.banner("HERMIAN alerts", ""));
        println!("{}", st.rule());
        println!("  {}", st.dim("No alerts recorded."));
        return Ok(());
    }

    println!(
        "{}",
        st.banner(
            "HERMIAN alerts",
            &format!(
                "{} shown{}",
                alerts.len(),
                match min {
                    Some(m) => format!(" \u{00B7} {}+", m.as_str()),
                    None => String::new(),
                }
            )
        )
    );
    println!("{}", st.rule());
    for a in &alerts {
        let sev = st.sev(a.severity, &format!("{:<8}", a.severity.as_str()));
        let when = a.ts.format("%m-%d %H:%M").to_string();
        let ref_short = a.ref_id.rsplit('-').next().unwrap_or(&a.ref_id);
        let repeats = if a.repeats > 1 {
            st.dim(&format!(" x{}", a.repeats))
        } else {
            String::new()
        };
        println!(
            "  {} {}  {} {}  {}{}",
            st.dim(&when),
            st.dim(&format!("{:>3}", ref_short)),
            sev,
            st.dim(&format!("{:<4}", a.detection.short())),
            a.title,
            repeats
        );
    }
    println!("{}", st.rule());
    println!(
        "  {}",
        st.dim(&format!(
            "hermian show <ref>  \u{00B7}  hermian collect <ref>  \u{00B7}  newest first, latest {}",
            ago(alerts[0].ts)
        ))
    );
    Ok(())
}

/// Accept a full ref or a bare sequence number for today. Anything else is
/// rejected: the result becomes part of a file path.
fn resolve_ref(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if let Ok(n) = trimmed.parse::<u32>() {
        return Some(format!("HER-{}-{:03}", Utc::now().format("%Y-%m%d"), n));
    }
    let upper = trimmed.to_ascii_uppercase();
    let valid = upper.starts_with("HER-")
        && upper.len() <= 64
        && upper.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    valid.then_some(upper)
}

pub fn load_alert(ref_id: &str) -> Result<Alert> {
    let ref_id = resolve_ref(ref_id).ok_or_else(|| {
        anyhow::anyhow!(
            "'{}' is not an alert reference (e.g. HER-2026-0923-004 or 4)",
            ref_id.escape_debug()
        )
    })?;
    let path = paths::alerts_dir().join(format!("{}.json", ref_id));
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            if let Some(err) = needs_root(&e) {
                return Err(err);
            }
            return Err(anyhow::Error::new(e).context(format!(
                "no alert {} (looked in {})",
                ref_id,
                paths::alerts_dir().display()
            )));
        }
    };
    serde_json::from_str::<Alert>(&text)
        .map(Alert::sanitized)
        .context("alert file is corrupt")
}

pub fn cmd_show(args: &ShowArgs) -> Result<()> {
    let alert = load_alert(&args.ref_id)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&alert)?);
    } else {
        print!("{}", render(&alert, Style::detect().theme()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_errors_say_to_use_sudo() {
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let msg = needs_root(&denied).unwrap().to_string();
        assert!(msg.contains("sudo"), "{}", msg);
        assert!(needs_root(&std::io::Error::from(std::io::ErrorKind::NotFound)).is_none());
    }

    #[test]
    fn refs_cannot_escape_the_alerts_dir() {
        assert_eq!(
            resolve_ref("her-2026-0923-004").as_deref(),
            Some("HER-2026-0923-004")
        );
        assert!(resolve_ref("7").unwrap().ends_with("-007"));
        assert!(resolve_ref("../../etc/shadow").is_none());
        assert!(resolve_ref("HER-../../x").is_none());
        assert!(resolve_ref("/etc/passwd").is_none());
    }
}
