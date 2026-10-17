//! Terminal presentation helpers shared by the CLI commands.
//!
//! Colour is enabled only when stdout is a TTY and `NO_COLOR` is unset (or
//! forced with `HERMIAN_COLOR=always`). Every helper degrades to plain text.

use hermian_core::{Severity, Theme};

pub const WIDTH: usize = 72;

#[derive(Clone, Copy)]
pub struct Style {
    pub color: bool,
}

impl Style {
    pub fn detect() -> Self {
        let force = std::env::var("HERMIAN_COLOR").ok();
        let color = match force.as_deref() {
            Some("always") => true,
            Some("never") => false,
            _ => std::env::var_os("NO_COLOR").is_none() && stdout_is_tty(),
        };
        Style { color }
    }

    pub fn theme(&self) -> Theme {
        if self.color {
            Theme::Ansi
        } else {
            Theme::Plain
        }
    }

    fn wrap(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{}m{}\x1b[0m", code, s)
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }

    pub fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }

    pub fn label(&self, s: &str) -> String {
        self.wrap("38;5;245", s)
    }

    pub fn ok(&self, s: &str) -> String {
        self.wrap("38;5;114", s)
    }

    pub fn warn(&self, s: &str) -> String {
        self.wrap("38;5;214", s)
    }

    pub fn bad(&self, s: &str) -> String {
        self.wrap("1;38;5;204", s)
    }

    /// Severity in the identity's palette: CRITICAL in the brand red, HIGH
    /// in the accent purple, LOW and INFO in quieter greys.
    pub fn sev(&self, s: Severity, text: &str) -> String {
        let code = match s {
            Severity::Critical => "1;38;5;204",
            Severity::High => "1;38;5;141",
            Severity::Low => "38;5;146",
            Severity::Info => "38;5;244",
        };
        self.wrap(code, text)
    }

    /// A thin rule, indented like the text so it lines up with the
    /// masthead and the rows (columns 3 to WIDTH).
    pub fn rule(&self) -> String {
        format!("  {}", self.dim(&"\u{2500}".repeat(WIDTH - 2)))
    }

    /// Section heading, upper-cased and dimmed, indented like the rows.
    pub fn heading(&self, s: &str) -> String {
        format!("  {}", self.label(&s.to_uppercase()))
    }

    /// A closing line under the last rule, dimmed and indented.
    pub fn footer(&self, s: &str) -> String {
        format!("  {}", self.dim(s))
    }

    /// `label ........ value` row with dotted leader.
    pub fn row(&self, label: &str, value: &str) -> String {
        let indent = 2;
        let pad = WIDTH.saturating_sub(indent + label.chars().count() + value.chars().count() + 2);
        let leader = ".".repeat(pad.max(2));
        format!(
            "{}{} {} {}",
            " ".repeat(indent),
            label,
            self.dim(&leader),
            value
        )
    }

    /// The header every screen opens with, and the rule under it:
    ///
    /// ```text
    ///   ╱╱╱●  hermian  v0.1.0-beta.11                     web-01 · up 6h
    ///   ────────────────────────────────────────────────────────────────
    /// ```
    ///
    /// `what` is a version ("v0.1.0") or the screen's name ("alerts");
    /// `right` is context and may already carry colour.
    pub fn masthead(&self, what: &str, right: &str) -> String {
        let left_len =
            2 + BRAND_STROKES.chars().count() + 1 + 2 + "hermian".len() + 2 + what.chars().count();
        let pad = WIDTH.saturating_sub(left_len + visible_len(right)).max(2);
        format!(
            "  {}{}  {}  {}{}{}\n{}",
            BRAND_STROKES,
            self.accent(BRAND_DOT),
            self.bold("hermian"),
            self.dim(what),
            " ".repeat(pad),
            if right.contains('\x1b') {
                right.to_string()
            } else {
                self.dim(right)
            },
            self.rule()
        )
    }

    /// The brand accent (the logo's signal dot). Truecolor when the terminal
    /// says it supports it, the nearest 256-colour purple otherwise.
    pub fn accent(&self, s: &str) -> String {
        let truecolor = std::env::var("COLORTERM")
            .map(|v| v.contains("truecolor") || v.contains("24bit"))
            .unwrap_or(false);
        self.wrap(
            if truecolor {
                "38;2;154;140;247"
            } else {
                "38;5;141"
            },
            s,
        )
    }

    /// The identity in two lines: the mark (three strokes and the signal
    /// dot) beside the wordmark, then the tagline. As in the logo, only the
    /// dot carries colour; the rest uses the terminal's own text colour, so
    /// light themes work too.
    pub fn brand(&self, version: &str) -> String {
        format!(
            "  {}{}  {}  {}\n        {}",
            BRAND_STROKES,
            self.accent(BRAND_DOT),
            self.bold("hermian"),
            self.dim(&format!("v{}", version)),
            self.dim(TAGLINE)
        )
    }
}

/// The logo's three strokes and its dot, as terminal glyphs.
const BRAND_STROKES: &str = "\u{2571}\u{2571}\u{2571}";
const BRAND_DOT: &str = "\u{25CF}";
pub const TAGLINE: &str = "Silent by default. Loud when it matters.";

/// Printed width of `s`: characters, not counting ANSI colour codes.
pub fn visible_len(s: &str) -> usize {
    let mut n = 0;
    let mut in_esc = false;
    for c in s.chars() {
        match (in_esc, c) {
            (false, '\x1b') => in_esc = true,
            (true, 'm') => in_esc = false,
            (true, _) => {}
            (false, _) => n += 1,
        }
    }
    n
}

fn stdout_is_tty() -> bool {
    // SAFETY: isatty on a fixed, valid fd.
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

pub fn humanize_secs(total_secs: u64) -> String {
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if mins > 0 && days == 0 {
        parts.push(format!("{}m", mins));
    }
    if parts.is_empty() {
        parts.push(format!("{}s", secs));
    }
    parts.join(" ")
}

pub fn ago(ts: chrono::DateTime<chrono::Utc>) -> String {
    let d = chrono::Utc::now() - ts;
    let secs = d.num_seconds().max(0) as u64;
    if secs < 60 {
        "just now".to_string()
    } else {
        format!("{} ago", humanize_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brand_is_plain_without_colour() {
        let b = Style { color: false }.brand("1.2.3");
        assert_eq!(
            b,
            "  \u{2571}\u{2571}\u{2571}\u{25CF}  hermian  v1.2.3\n        Silent by default. Loud when it matters."
        );
        assert!(!b.contains('\x1b'));
    }

    #[test]
    fn only_the_dot_is_coloured() {
        let b = Style { color: true }.brand("1.2.3");
        // The strokes are bare text; the dot is the one coloured glyph.
        assert!(
            b.starts_with("  \u{2571}\u{2571}\u{2571}\x1b[38;"),
            "{:?}",
            b
        );
        assert!(b.contains("\u{25CF}\x1b[0m"), "{:?}", b);
        assert!(b.contains("\x1b[1mhermian\x1b[0m"), "{:?}", b);
    }

    #[test]
    fn masthead_fills_the_width() {
        let st = Style { color: false };
        let m = st.masthead("alerts", "8 shown");
        let first = m.lines().next().unwrap();
        assert!(first.starts_with("  \u{2571}\u{2571}\u{2571}\u{25CF}  hermian  alerts "));
        assert!(first.ends_with("8 shown"));
        assert_eq!(first.chars().count(), WIDTH);
        assert_eq!(m.lines().nth(1).unwrap(), st.rule());
    }

    #[test]
    fn masthead_width_ignores_colour() {
        let plain = Style { color: false }.masthead("v1", "up 2h");
        let col = Style { color: true }.masthead("v1", "up 2h");
        assert_eq!(
            visible_len(col.lines().next().unwrap()),
            visible_len(plain.lines().next().unwrap())
        );
    }

    #[test]
    fn visible_len_skips_escapes() {
        assert_eq!(visible_len("\x1b[1;38;5;204mHIGH\x1b[0m x"), 6);
        assert_eq!(visible_len("\u{25CF}"), 1);
    }

    #[test]
    fn headings_and_footers_line_up_with_rows() {
        let st = Style { color: false };
        assert_eq!(st.heading("Coverage"), "  COVERAGE");
        assert_eq!(st.footer("done"), "  done");
        assert!(st.row("a", "b").starts_with("  a "));
    }
}
