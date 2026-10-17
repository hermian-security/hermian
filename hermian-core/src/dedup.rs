//! Signature-based deduplication.
//!
//! The first occurrence of a signature is emitted immediately. Repeats inside the
//! window are counted, and when the window closes a single summary finding is
//! produced so the operator learns "this kept happening" without N notifications.
//!
//! One incident, one page: rules keep per-event detail (a destination, an
//! executable) out of the signature and name it with [`Finding::varies`]; the
//! summary lists the values it folded. An incident still recurring when its
//! window closes gets a longer one next time (5, 15, 45 minutes, then hourly
//! with the default window), so a miner that keeps calling out pages a few
//! times an hour instead of every five minutes. A quiet window resets it.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

use crate::alert::Finding;
use crate::events::{DetectionId, Severity};

pub struct Deduper {
    window: Duration,
    entries: HashMap<String, DedupEntry>,
}

struct DedupEntry {
    last_emitted: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    repeats: u32,
    detection: DetectionId,
    severity: Severity,
    title: String,
    /// Consecutive windows that ended with repeats; lengthens the window.
    streak: u32,
    /// The last window closed with repeats (a summary went out).
    recurring: bool,
    /// Distinct `varies` values seen since the last emit, in order.
    varies_label: Option<String>,
    varies_seen: Vec<String>,
    varies_overflow: bool,
}

impl DedupEntry {
    fn note_varies(&mut self, finding: &Finding) {
        let Some(v) = &finding.varies else { return };
        self.varies_label.get_or_insert_with(|| v.label.clone());
        if self.varies_seen.contains(&v.value) {
            return;
        }
        if self.varies_seen.len() < MAX_VARIES {
            self.varies_seen.push(v.value.clone());
        } else {
            self.varies_overflow = true;
        }
    }

    fn reset_window(&mut self, now: DateTime<Utc>, finding: &Finding) {
        self.last_emitted = now;
        self.repeats = 0;
        self.varies_seen.clear();
        self.varies_overflow = false;
        self.note_varies(finding);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Emit,
    Suppressed,
}

/// Entries idle for this many windows are dropped to bound memory.
const RETENTION_WINDOWS: i32 = 12;
/// Hard cap on remembered signatures.
pub const MAX_ENTRIES: usize = 20_000;
/// Distinct varying values remembered per incident (for the summary).
const MAX_VARIES: usize = 64;
/// Values printed in a summary; the rest are counted.
const SHOWN_VARIES: usize = 5;
/// Each recurring window is this many times the previous one...
const STREAK_FACTOR: i32 = 3;
/// ...up to this long (or the configured window, if that's longer).
const MAX_STREAK_WINDOW_SECS: i64 = 3_600;

impl Deduper {
    pub fn new(window_secs: u64) -> Self {
        Deduper {
            window: Duration::seconds(window_secs.clamp(1, crate::config::MAX_WINDOW_SECS) as i64),
            entries: HashMap::new(),
        }
    }

    pub fn record(&mut self, signature: &str, now: DateTime<Utc>, finding: &Finding) -> Decision {
        let base = self.window;
        match self.entries.get_mut(signature) {
            Some(entry) => {
                let window = window_for(base, entry.streak);
                entry.last_seen = now;
                // Escalation always breaks through the window.
                if finding.severity > entry.severity {
                    entry.severity = finding.severity;
                    entry.title = finding.title.clone();
                    entry.reset_window(now, finding);
                    return Decision::Emit;
                }
                if now - entry.last_emitted < window {
                    entry.repeats += 1;
                    entry.note_varies(finding);
                    Decision::Suppressed
                } else {
                    // Still going since the last window: stretch the next one.
                    entry.streak = if entry.recurring || entry.repeats > 0 {
                        entry.streak.saturating_add(1).min(16)
                    } else {
                        0
                    };
                    entry.recurring = false;
                    entry.reset_window(now, finding);
                    Decision::Emit
                }
            }
            None => {
                // Signatures carry attacker-influenced text (paths, comms):
                // bound the map by forgetting the longest-idle entry.
                if self.entries.len() >= MAX_ENTRIES {
                    let idle = self
                        .entries
                        .iter()
                        .min_by_key(|(_, e)| e.last_seen)
                        .map(|(k, _)| k.clone());
                    if let Some(k) = idle {
                        self.entries.remove(&k);
                    }
                }
                let mut entry = DedupEntry {
                    last_emitted: now,
                    last_seen: now,
                    repeats: 0,
                    detection: finding.detection,
                    severity: finding.severity,
                    title: finding.title.clone(),
                    streak: 0,
                    recurring: false,
                    varies_label: None,
                    varies_seen: Vec::new(),
                    varies_overflow: false,
                };
                entry.note_varies(finding);
                self.entries.insert(signature.to_string(), entry);
                Decision::Emit
            }
        }
    }

    /// Close expired windows: emit one summary per signature that repeated, and
    /// prune long-idle entries.
    pub fn tick(&mut self, now: DateTime<Utc>) -> Vec<Finding> {
        let base = self.window;
        let mut summaries = Vec::new();
        for (sig, e) in self.entries.iter_mut() {
            let window = window_for(base, e.streak);
            if now - e.last_emitted < window {
                continue;
            }
            if e.repeats == 0 {
                // A quiet window: the incident is over, start afresh next time.
                e.recurring = false;
                continue;
            }
            e.recurring = true;
            // Only actionable patterns earn a summary: knowing a HIGH kept
            // recurring matters, knowing an INFO did is noise. Summaries are
            // LOW so they are logged distinctly but never page.
            if !e.severity.is_actionable() {
                e.repeats = 0;
                continue;
            }
            let mut summary = Finding::new(
                e.detection,
                Severity::Low,
                &format!("Repeated: {}", e.title),
                &format!("summary|{}", sig),
            )
            .what(format!(
                "The pattern \"{}\" recurred {} more time{} within {} minutes of the \
                 original alert and was folded into this summary.",
                e.title,
                e.repeats,
                if e.repeats == 1 { "" } else { "s" },
                window.num_minutes()
            ))
            .why(
                "Repeats of one incident are deduplicated so it produces one notification. \
                 This summary closes the window; an incident that keeps going gets a longer \
                 window next time.",
            );
            if let Some(label) = &e.varies_label {
                summary = summary.fact(
                    label.clone(),
                    varies_text(&e.varies_seen, e.varies_overflow),
                );
            }
            summaries.push(summary);
            e.repeats = 0;
            e.varies_seen.clear();
            e.varies_overflow = false;
        }
        self.entries
            .retain(|_, e| now - e.last_seen < window_for(base, e.streak) * RETENTION_WINDOWS);
        summaries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The window for an incident that recurred through `streak` windows.
fn window_for(base: Duration, streak: u32) -> Duration {
    let cap = Duration::seconds(MAX_STREAK_WINDOW_SECS).max(base);
    let mut w = base;
    for _ in 0..streak {
        w = w * STREAK_FACTOR;
        if w >= cap {
            return cap;
        }
    }
    w
}

/// "a, b, c, d, e, ... (17 distinct)"; "64+" once the list is full.
fn varies_text(seen: &[String], overflow: bool) -> String {
    let shown = seen
        .iter()
        .take(SHOWN_VARIES)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if seen.len() <= SHOWN_VARIES && !overflow {
        return shown;
    }
    let total = if overflow {
        format!("{}+", seen.len())
    } else {
        seen.len().to_string()
    };
    format!("{}, ... ({} distinct)", shown, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(sig: &str, sev: Severity) -> Finding {
        Finding::new(DetectionId::D1, sev, "web shell", sig)
    }

    #[test]
    fn suppresses_within_window() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        assert_eq!(
            d.record("a", t0, &finding("a", Severity::High)),
            Decision::Emit
        );
        assert_eq!(
            d.record(
                "a",
                t0 + Duration::seconds(60),
                &finding("a", Severity::High)
            ),
            Decision::Suppressed
        );
        assert_eq!(
            d.record(
                "b",
                t0 + Duration::seconds(61),
                &finding("b", Severity::High)
            ),
            Decision::Emit
        );
    }

    #[test]
    fn escalation_breaks_through() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        d.record("a", t0, &finding("a", Severity::High));
        assert_eq!(
            d.record(
                "a",
                t0 + Duration::seconds(5),
                &finding("a", Severity::Critical)
            ),
            Decision::Emit
        );
    }

    #[test]
    fn summary_after_window() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        d.record("a", t0, &finding("a", Severity::High));
        d.record(
            "a",
            t0 + Duration::seconds(10),
            &finding("a", Severity::High),
        );
        d.record(
            "a",
            t0 + Duration::seconds(20),
            &finding("a", Severity::High),
        );
        assert!(d.tick(t0 + Duration::seconds(100)).is_empty());
        let summaries = d.tick(t0 + Duration::seconds(301));
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].severity, Severity::Low);
        assert!(summaries[0].what.contains("2 more times"));
        // Second tick has nothing new.
        assert!(d.tick(t0 + Duration::seconds(302)).is_empty());
    }

    #[test]
    fn varying_detail_is_listed_in_the_summary() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        for i in 0..3 {
            let f = finding("a", Severity::High).varies("Destinations", format!("10.0.0.{}", i));
            d.record("a", t0 + Duration::seconds(i), &f);
        }
        let s = d.tick(t0 + Duration::seconds(301));
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].facts[0].label, "Destinations");
        // The first, emitted value is listed too: the summary covers the incident.
        assert_eq!(s[0].facts[0].value, "10.0.0.0, 10.0.0.1, 10.0.0.2");
    }

    #[test]
    fn many_values_are_counted_not_all_printed() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        for i in 0..100 {
            let f = finding("a", Severity::High).varies("Destinations", format!("v{}", i));
            d.record("a", t0 + Duration::milliseconds(i), &f);
        }
        let s = d.tick(t0 + Duration::seconds(301));
        assert_eq!(
            s[0].facts[0].value,
            "v0, v1, v2, v3, v4, ... (64+ distinct)"
        );
    }

    /// The fake httpd on buki spawned a shell every ~5 minutes, just past the
    /// window, so each one paged. A recurring incident gets a longer window.
    #[test]
    fn recurring_incident_stretches_the_window() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        let f = finding("a", Severity::High);
        let at = |s| t0 + Duration::seconds(s);
        assert_eq!(d.record("a", at(0), &f), Decision::Emit);
        assert_eq!(d.record("a", at(150), &f), Decision::Suppressed);
        assert_eq!(d.tick(at(300)).len(), 1);
        // Still going after a window with repeats: pages, then 15 minutes.
        assert_eq!(d.record("a", at(310), &f), Decision::Emit);
        assert_eq!(d.record("a", at(310 + 600), &f), Decision::Suppressed);
        assert_eq!(d.tick(at(310 + 900)).len(), 1);
        // Then 45 minutes.
        assert_eq!(d.record("a", at(1300), &f), Decision::Emit);
        assert_eq!(d.record("a", at(1300 + 2600), &f), Decision::Suppressed);
        assert_eq!(d.tick(at(1300 + 2700)).len(), 1);
        // Then capped at an hour.
        assert_eq!(d.record("a", at(4100), &f), Decision::Emit);
        assert_eq!(d.record("a", at(4100 + 3599), &f), Decision::Suppressed);
        assert_eq!(d.record("a", at(4100 + 3600), &f), Decision::Emit);
    }

    #[test]
    fn a_quiet_window_resets_the_stretch() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        let f = finding("a", Severity::High);
        let at = |s| t0 + Duration::seconds(s);
        d.record("a", at(0), &f);
        d.record("a", at(100), &f);
        d.tick(at(300));
        assert_eq!(d.record("a", at(310), &f), Decision::Emit); // 15 min window now
        d.tick(at(310 + 900)); // nothing happened in it
        assert_eq!(d.record("a", at(1300), &f), Decision::Emit);
        // Back to five minutes.
        assert_eq!(d.record("a", at(1300 + 301), &f), Decision::Emit);
    }

    #[test]
    fn info_repeats_produce_no_summary() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        for i in 0..5 {
            d.record(
                "i",
                t0 + Duration::seconds(i),
                &finding("i", Severity::Info),
            );
        }
        assert!(d.tick(t0 + Duration::seconds(301)).is_empty());
    }

    #[test]
    fn entry_count_is_bounded() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        for i in 0..(MAX_ENTRIES + 50) {
            let sig = format!("s{}", i);
            d.record(
                &sig,
                t0 + Duration::milliseconds(i as i64),
                &finding(&sig, Severity::Info),
            );
        }
        assert_eq!(d.len(), MAX_ENTRIES);
    }

    #[test]
    fn idle_entries_are_pruned() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        d.record("a", t0, &finding("a", Severity::Info));
        assert_eq!(d.len(), 1);
        d.tick(t0 + Duration::seconds(300 * 13));
        assert!(d.is_empty());
    }
}
