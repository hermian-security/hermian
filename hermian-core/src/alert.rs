//! Alert model and rendering.
//!
//! A [`Finding`] is what a detection rule produces. The engine promotes it to an
//! [`Alert`] by attaching a reference id, host, and timestamp. Rendering is a
//! pure function of the alert plus a [`Theme`], so the exact same alert can be
//! written to journald (plain), a terminal (ansi) or a chat webhook (compact).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::events::{DetectionId, ProcInfo, Severity};

/// One node of a process ancestry, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainNode {
    pub pid: u32,
    pub uid: u32,
    pub user: Option<String>,
    pub comm: String,
    pub exe: String,
    /// Marks the process the detection is about (rendered with emphasis).
    #[serde(default)]
    pub focus: bool,
}

impl ChainNode {
    pub fn from_proc(p: &ProcInfo, user_names: &HashMap<u32, String>) -> Self {
        ChainNode {
            pid: p.pid,
            uid: p.uid,
            user: user_names.get(&p.uid).cloned(),
            comm: p.comm.clone(),
            exe: p.exe.clone(),
            focus: false,
        }
    }

    fn user_label(&self) -> String {
        match &self.user {
            Some(u) => u.clone(),
            None => format!("uid {}", self.uid),
        }
    }
}

/// Build a chain from a process tree slice, marking the last node as the focus.
pub fn chain_from_procs(chain: &[ProcInfo], user_names: &HashMap<u32, String>) -> Vec<ChainNode> {
    let mut out: Vec<ChainNode> = chain
        .iter()
        .map(|p| ChainNode::from_proc(p, user_names))
        .collect();
    if let Some(last) = out.last_mut() {
        last.focus = true;
    }
    out
}

/// A labelled fact shown in the alert's evidence block (e.g. `Path`, `Writer`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub detection: DetectionId,
    pub severity: Severity,
    pub title: String,
    pub what: String,
    #[serde(default)]
    pub chain: Vec<ChainNode>,
    #[serde(default)]
    pub facts: Vec<Fact>,
    pub why: String,
    #[serde(default)]
    pub actions: Vec<String>,
    pub signature: String,
    #[serde(default)]
    pub pids: Vec<u32>,
}

impl Finding {
    pub fn new(detection: DetectionId, severity: Severity, title: &str, signature: &str) -> Self {
        Finding {
            detection,
            severity,
            title: title.to_string(),
            what: String::new(),
            chain: Vec::new(),
            facts: Vec::new(),
            why: String::new(),
            actions: Vec::new(),
            signature: signature.to_string(),
            pids: Vec::new(),
        }
    }

    pub fn what(mut self, what: impl Into<String>) -> Self {
        self.what = what.into();
        self
    }

    /// Attach a process chain; also records the chain's PIDs for correlation.
    pub fn chain(mut self, chain: Vec<ChainNode>) -> Self {
        if self.pids.is_empty() {
            self.pids = chain.iter().map(|n| n.pid).collect();
        }
        self.chain = chain;
        self
    }

    pub fn fact(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        if !value.is_empty() {
            self.facts.push(Fact {
                label: label.into(),
                value,
            });
        }
        self
    }

    pub fn why(mut self, why: impl Into<String>) -> Self {
        self.why = why.into();
        self
    }

    pub fn action(mut self, step: impl Into<String>) -> Self {
        let step = step.into();
        if !step.is_empty() {
            self.actions.push(step);
        }
        self
    }

    pub fn actions<I, S>(mut self, steps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for s in steps {
            self = self.action(s);
        }
        self
    }

    pub fn pids(mut self, pids: Vec<u32>) -> Self {
        self.pids = pids;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub ref_id: String,
    pub ts: DateTime<Utc>,
    pub host: String,
    pub severity: Severity,
    pub detection: DetectionId,
    pub title: String,
    pub what: String,
    #[serde(default)]
    pub chain: Vec<ChainNode>,
    #[serde(default)]
    pub chain_pids: Vec<u32>,
    #[serde(default)]
    pub facts: Vec<Fact>,
    pub why: String,
    #[serde(default)]
    pub actions: Vec<String>,
    pub signature: String,
    /// Number of identical occurrences folded into this alert (>= 1).
    #[serde(default = "one")]
    pub repeats: u32,
}

fn one() -> u32 {
    1
}

impl Alert {
    pub fn from_finding(finding: Finding, ref_id: String, host: String, ts: DateTime<Utc>) -> Self {
        Alert {
            ref_id,
            ts,
            host,
            severity: finding.severity,
            detection: finding.detection,
            title: finding.title,
            what: finding.what,
            chain_pids: finding.pids,
            chain: finding.chain,
            facts: finding.facts,
            why: finding.why,
            actions: finding.actions,
            signature: finding.signature,
            repeats: 1,
        }
    }

    /// One-line summary suitable for logs and chat previews.
    pub fn headline(&self) -> String {
        format!(
            "{} {} {} - {} [{}]",
            self.severity.as_str(),
            self.detection.short(),
            self.host,
            self.title,
            self.ref_id
        )
    }
}

// ---------------------------------------------------------------------------
// Reference ids
// ---------------------------------------------------------------------------

/// Generates `HER-YYYY-MMDD-NNN` ids that reset daily. The counter is meant to
/// be persisted by the daemon and restored via [`RefGen::resume`] so a restart
/// never reissues an id already used today.
#[derive(Debug, Clone)]
pub struct RefGen {
    day: String,
    seq: u32,
}

fn day_key(now: DateTime<Utc>) -> String {
    now.format("%Y-%m%d").to_string()
}

impl RefGen {
    pub fn new(now: DateTime<Utc>) -> Self {
        RefGen {
            day: day_key(now),
            seq: 0,
        }
    }

    /// Resume from a persisted `(day, seq)` pair; ignored if the day differs.
    pub fn resume(now: DateTime<Utc>, day: &str, seq: u32) -> Self {
        let today = day_key(now);
        if day == today {
            RefGen { day: today, seq }
        } else {
            RefGen::new(now)
        }
    }

    pub fn next(&mut self, now: DateTime<Utc>) -> String {
        let day = day_key(now);
        if day != self.day {
            self.day = day;
            self.seq = 0;
        }
        self.seq += 1;
        format!("HER-{}-{:03}", self.day, self.seq)
    }

    pub fn state(&self) -> (&str, u32) {
        (&self.day, self.seq)
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Output theme. `Plain` is safe for journald/files, `Ansi` for a TTY, `Compact`
/// is a dense single-block form for chat webhooks and `hermian alerts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Plain,
    Ansi,
    Compact,
}

pub const WIDTH: usize = 72;
const GUTTER: usize = 2;
const LABEL_W: usize = 12;

struct Palette {
    reset: &'static str,
    bold: &'static str,
    dim: &'static str,
    label: &'static str,
    focus: &'static str,
    sev: &'static str,
}

const NO_COLOR: Palette = Palette {
    reset: "",
    bold: "",
    dim: "",
    label: "",
    focus: "",
    sev: "",
};

fn palette(theme: Theme, severity: Severity) -> Palette {
    if theme != Theme::Ansi {
        return NO_COLOR;
    }
    let sev = match severity {
        Severity::Critical => "\x1b[1;38;5;196m",
        Severity::High => "\x1b[1;38;5;208m",
        Severity::Low => "\x1b[1;38;5;220m",
        Severity::Info => "\x1b[1;38;5;245m",
    };
    Palette {
        reset: "\x1b[0m",
        bold: "\x1b[1m",
        dim: "\x1b[2m",
        label: "\x1b[38;5;245m",
        focus: "\x1b[1;38;5;255m",
        sev,
    }
}

fn severity_glyph(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "\u{25A0}\u{25A0}\u{25A0}\u{25A0}", // ■■■■
        Severity::High => "\u{25A0}\u{25A0}\u{25A0}\u{25A1}",     // ■■■□
        Severity::Low => "\u{25A0}\u{25A0}\u{25A1}\u{25A1}",      // ■■□□
        Severity::Info => "\u{25A0}\u{25A1}\u{25A1}\u{25A1}",     // ■□□□
    }
}

fn char_len(s: &str) -> usize {
    s.chars().count()
}

/// Greedy word wrap that respects explicit newlines.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split_whitespace() {
            if !line.is_empty() && char_len(&line) + 1 + char_len(word) > width {
                lines.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        lines.push(line);
    }
    // Trim trailing empties produced by a trailing newline.
    while lines.last().map(|l| l.is_empty()).unwrap_or(false) && lines.len() > 1 {
        lines.pop();
    }
    lines
}

fn rule(ch: char, width: usize) -> String {
    ch.to_string().repeat(width)
}

fn push_section(out: &mut String, p: &Palette, title: &str) {
    out.push('\n');
    out.push_str(&format!("{}{}{}\n", p.label, title.to_uppercase(), p.reset));
}

fn push_paragraph(out: &mut String, text: &str) {
    let indent = " ".repeat(GUTTER);
    for l in wrap(text, WIDTH - GUTTER) {
        out.push_str(&indent);
        out.push_str(&l);
        out.push('\n');
    }
}

fn push_kv(out: &mut String, p: &Palette, label: &str, value: &str) {
    push_kv_w(out, p, label, value, LABEL_W);
}

/// Key/value row with an explicit label column width (used so every row in a
/// block shares one width even when a label is long).
fn push_kv_w(out: &mut String, p: &Palette, label: &str, value: &str, label_w: usize) {
    let indent = " ".repeat(GUTTER);
    // Always leave at least two spaces between label and value, even for long labels.
    let width = label_w.max(char_len(label) + 2);
    let lab = format!("{:<w$}", label, w = width);
    let avail = WIDTH.saturating_sub(GUTTER + width);
    let lines = wrap(value, avail.max(16));
    for (i, l) in lines.iter().enumerate() {
        if i == 0 {
            out.push_str(&format!("{}{}{}{}{}\n", indent, p.label, lab, p.reset, l));
        } else {
            out.push_str(&format!("{}{}{}\n", indent, " ".repeat(width), l));
        }
    }
}

fn shorten_path(path: &str, max: usize) -> String {
    if char_len(path) <= max {
        return path.to_string();
    }
    // Keep the tail (file name is what matters), prefix with an ellipsis.
    let tail: String = path
        .chars()
        .rev()
        .take(max.saturating_sub(1))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("\u{2026}{}", tail)
}

fn push_chain(out: &mut String, p: &Palette, chain: &[ChainNode]) {
    let indent = " ".repeat(GUTTER);
    for (i, node) in chain.iter().enumerate() {
        let connector = if i == 0 {
            String::new()
        } else {
            format!("{}\u{2514}\u{2500} ", " ".repeat((i - 1) * 3))
        };
        let (open, close) = if node.focus {
            (p.focus, p.reset)
        } else {
            ("", "")
        };
        let head = format!("{}{}{}{}{}", indent, connector, open, node.comm, close);
        let meta = format!(
            "{}{} \u{00B7} pid {}{}",
            p.dim,
            node.user_label(),
            node.pid,
            p.reset
        );
        out.push_str(&format!("{}  {}\n", head, meta));
        if !node.exe.is_empty()
            && node.exe != node.comm
            && !node.exe.ends_with(&format!("/{}", node.comm))
        {
            let pad = " ".repeat(GUTTER + connector.chars().count());
            let avail = WIDTH.saturating_sub(pad.len() + 2);
            out.push_str(&format!(
                "{}  {}{}{}\n",
                pad,
                p.dim,
                shorten_path(&node.exe, avail),
                p.reset
            ));
        }
    }
}

/// Render an alert in the given theme.
pub fn render(alert: &Alert, theme: Theme) -> String {
    match theme {
        Theme::Compact => render_compact(alert),
        _ => render_block(alert, theme),
    }
}

/// Backwards-compatible default: plain theme.
pub fn render_alert(alert: &Alert) -> String {
    render(alert, Theme::Plain)
}

fn render_block(alert: &Alert, theme: Theme) -> String {
    let p = palette(theme, alert.severity);
    let mut out = String::with_capacity(1024);

    // Header band: severity left, ref right.
    let heavy = rule('\u{2501}', WIDTH);
    let light = rule('\u{2500}', WIDTH);
    let left = format!(
        "{} HERMIAN  {}",
        severity_glyph(alert.severity),
        alert.severity.as_str()
    );
    let right = alert.ref_id.clone();
    let pad = WIDTH.saturating_sub(char_len(&left) + char_len(&right));
    out.push_str(&format!("{}{}{}\n", p.sev, heavy, p.reset));
    out.push_str(&format!(
        "{}{}{}{}{}{}{}\n",
        p.sev,
        left,
        p.reset,
        " ".repeat(pad),
        p.dim,
        right,
        p.reset
    ));
    out.push_str(&format!("{}{}{}\n", p.sev, heavy, p.reset));

    // Title
    out.push('\n');
    for l in wrap(&alert.title, WIDTH) {
        out.push_str(&format!("{}{}{}\n", p.bold, l, p.reset));
    }
    if alert.repeats > 1 {
        out.push_str(&format!(
            "{}Seen {} times in the deduplication window.{}\n",
            p.dim, alert.repeats, p.reset
        ));
    }
    out.push('\n');

    // Metadata grid
    push_kv(&mut out, &p, "Host", &alert.host);
    push_kv(
        &mut out,
        &p,
        "Time",
        &alert.ts.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );
    push_kv(
        &mut out,
        &p,
        "Detection",
        &format!("{}  {}", alert.detection.short(), alert.detection.name()),
    );

    // Evidence
    if !alert.what.is_empty() || !alert.chain.is_empty() || !alert.facts.is_empty() {
        push_section(&mut out, &p, "What happened");
        if !alert.what.is_empty() {
            push_paragraph(&mut out, &alert.what);
        }
        if !alert.chain.is_empty() {
            out.push('\n');
            push_chain(&mut out, &p, &alert.chain);
        }
        if !alert.facts.is_empty() {
            out.push('\n');
            let w = alert
                .facts
                .iter()
                .map(|f| char_len(&f.label) + 2)
                .max()
                .unwrap_or(0)
                .max(LABEL_W);
            for f in &alert.facts {
                push_kv_w(&mut out, &p, &f.label, &f.value, w);
            }
        }
    }

    if !alert.why.is_empty() {
        push_section(&mut out, &p, "Why this matters");
        push_paragraph(&mut out, &alert.why);
    }

    if !alert.actions.is_empty() {
        push_section(&mut out, &p, "Recommended action");
        for (i, step) in alert.actions.iter().enumerate() {
            let num = format!("{:>2}. ", i + 1);
            let lines = wrap(step, WIDTH - GUTTER - num.len());
            for (j, l) in lines.iter().enumerate() {
                if j == 0 {
                    out.push_str(&format!(
                        "{}{}{}{}{}\n",
                        " ".repeat(GUTTER),
                        p.bold,
                        num,
                        p.reset,
                        l
                    ));
                } else {
                    out.push_str(&format!(
                        "{}{}{}\n",
                        " ".repeat(GUTTER),
                        " ".repeat(num.len()),
                        l
                    ));
                }
            }
        }
    }

    // Footer
    out.push('\n');
    out.push_str(&format!("{}{}{}\n", p.dim, light, p.reset));
    let footer_l = format!("hermian show {}", alert.ref_id);
    let footer_r = format!("hermian collect {}", alert.ref_id);
    let pad = WIDTH.saturating_sub(char_len(&footer_l) + char_len(&footer_r));
    out.push_str(&format!(
        "{}{}{}{}{}\n",
        p.dim,
        footer_l,
        " ".repeat(pad),
        footer_r,
        p.reset
    ));
    out
}

fn render_compact(alert: &Alert) -> String {
    let mut out = String::with_capacity(512);
    out.push_str(&format!(
        "{} HERMIAN {} \u{00B7} {} \u{00B7} {}\n",
        severity_glyph(alert.severity),
        alert.severity.as_str(),
        alert.host,
        alert.ts.format("%Y-%m-%d %H:%M UTC")
    ));
    out.push_str(&format!("{}\n", alert.title));
    if !alert.what.is_empty() {
        out.push_str(&alert.what);
        out.push('\n');
    }
    if !alert.chain.is_empty() {
        let path: Vec<String> = alert
            .chain
            .iter()
            .map(|n| format!("{}({})", n.comm, n.pid))
            .collect();
        out.push_str(&format!("chain: {}\n", path.join(" \u{2192} ")));
    }
    for f in &alert.facts {
        out.push_str(&format!("{}: {}\n", f.label.to_lowercase(), f.value));
    }
    if !alert.actions.is_empty() {
        out.push_str(&format!("next: {}\n", alert.actions[0]));
    }
    out.push_str(&format!("ref: {}", alert.ref_id));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::DetectionId;

    fn sample_alert() -> Alert {
        let chain = vec![
            ChainNode {
                pid: 1842,
                uid: 33,
                user: Some("www-data".into()),
                comm: "nginx".into(),
                exe: "/usr/sbin/nginx".into(),
                focus: false,
            },
            ChainNode {
                pid: 3107,
                uid: 33,
                user: Some("www-data".into()),
                comm: "bash".into(),
                exe: "/usr/bin/bash".into(),
                focus: false,
            },
            ChainNode {
                pid: 3110,
                uid: 33,
                user: Some("www-data".into()),
                comm: "sh".into(),
                exe: "/tmp/.x.sh".into(),
                focus: true,
            },
        ];
        let f = Finding::new(
            DetectionId::D1,
            Severity::Critical,
            "Web server chain downloaded and executed remote content",
            "d1|nginx-bash-curl",
        )
        .what("The web server nginx spawned a shell, which used curl to download content, and that content is now executing.")
        .chain(chain)
        .fact("Payload", "/tmp/.x.sh")
        .why("This exact chain is the signature of remote code execution against a web application.")
        .actions([
            "Isolate this host from the network if the activity is unexpected.",
            "Review nginx access logs around the alert time.",
        ]);
        Alert::from_finding(
            f,
            "HER-2025-0914-001".into(),
            "web-prod-01".into(),
            Utc::now(),
        )
    }

    #[test]
    fn plain_render_has_sections_and_no_ansi() {
        let r = render(&sample_alert(), Theme::Plain);
        assert!(r.contains("HERMIAN  CRITICAL"));
        assert!(r.contains("HER-2025-0914-001"));
        assert!(r.contains("WHAT HAPPENED"));
        assert!(r.contains("WHY THIS MATTERS"));
        assert!(r.contains("RECOMMENDED ACTION"));
        assert!(r.contains("nginx"));
        assert!(r.contains("\u{2514}\u{2500} sh"));
        assert!(r.contains("hermian collect HER-2025-0914-001"));
        assert!(!r.contains("\x1b["));
        for line in r.lines() {
            assert!(line.chars().count() <= WIDTH, "line too wide: {:?}", line);
        }
    }

    #[test]
    fn ansi_render_is_coloured() {
        let r = render(&sample_alert(), Theme::Ansi);
        assert!(r.contains("\x1b["));
    }

    #[test]
    fn compact_render_is_dense() {
        let r = render(&sample_alert(), Theme::Compact);
        assert!(r.lines().count() <= 8);
        assert!(r.contains("nginx(1842) \u{2192} bash(3107) \u{2192} sh(3110)"));
        assert!(r.ends_with("ref: HER-2025-0914-001"));
    }

    #[test]
    fn alert_json_roundtrip() {
        let a = sample_alert();
        let json = serde_json::to_string(&a).unwrap();
        let back: Alert = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ref_id, a.ref_id);
        assert_eq!(back.chain.len(), 3);
        assert!(back.chain[2].focus);
    }

    #[test]
    fn refgen_resets_per_day_and_resumes() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::days(1);
        let mut g = RefGen::new(t1);
        assert_eq!(g.next(t1), format!("HER-{}-001", t1.format("%Y-%m%d")));
        assert_eq!(g.next(t1), format!("HER-{}-002", t1.format("%Y-%m%d")));
        assert_eq!(g.next(t2), format!("HER-{}-001", t2.format("%Y-%m%d")));

        let (day, seq) = g.state();
        let mut resumed = RefGen::resume(t2, day, seq);
        assert_eq!(
            resumed.next(t2),
            format!("HER-{}-002", t2.format("%Y-%m%d"))
        );

        let mut stale = RefGen::resume(t2, "1999-0101", 40);
        assert_eq!(stale.next(t2), format!("HER-{}-001", t2.format("%Y-%m%d")));
    }

    #[test]
    fn wrap_respects_width_and_newlines() {
        let lines = wrap("one two three four five six seven eight nine ten", 12);
        assert!(lines.iter().all(|l| l.chars().count() <= 12));
        let lines = wrap("a\nb", 80);
        assert_eq!(lines, vec!["a", "b"]);
    }
}
