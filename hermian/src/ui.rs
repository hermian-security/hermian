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
        self.wrap("1;38;5;196", s)
    }

    pub fn sev(&self, s: Severity, text: &str) -> String {
        let code = match s {
            Severity::Critical => "1;38;5;196",
            Severity::High => "1;38;5;208",
            Severity::Low => "38;5;220",
            Severity::Info => "38;5;245",
        };
        self.wrap(code, text)
    }

    /// Heavy rule the full width.
    pub fn rule(&self) -> String {
        self.dim(&"\u{2500}".repeat(WIDTH))
    }

    /// Section heading, upper-cased and dimmed.
    pub fn heading(&self, s: &str) -> String {
        self.label(&s.to_uppercase())
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

    /// Two-column header line: left bold, right dimmed, aligned to WIDTH.
    pub fn banner(&self, left: &str, right: &str) -> String {
        let pad = WIDTH.saturating_sub(left.chars().count() + right.chars().count());
        format!("{}{}{}", self.bold(left), " ".repeat(pad), self.dim(right))
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
}
