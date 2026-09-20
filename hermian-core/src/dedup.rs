//! Signature-based deduplication.
//!
//! The first occurrence of a signature is emitted immediately. Repeats inside the
//! window are counted, and when the window closes a single summary finding is
//! produced so the operator learns "this kept happening" without N notifications.

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
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Emit,
    Suppressed,
}

/// Entries idle for this many windows are dropped to bound memory.
const RETENTION_WINDOWS: i32 = 12;

impl Deduper {
    pub fn new(window_secs: u64) -> Self {
        Deduper {
            window: Duration::seconds(window_secs.max(1) as i64),
            entries: HashMap::new(),
        }
    }

    pub fn record(&mut self, signature: &str, now: DateTime<Utc>, finding: &Finding) -> Decision {
        match self.entries.get_mut(signature) {
            Some(entry) => {
                entry.last_seen = now;
                // Escalation always breaks through the window.
                if finding.severity > entry.severity {
                    entry.severity = finding.severity;
                    entry.title = finding.title.clone();
                    entry.last_emitted = now;
                    entry.repeats = 0;
                    return Decision::Emit;
                }
                if now - entry.last_emitted < self.window {
                    entry.repeats += 1;
                    Decision::Suppressed
                } else {
                    entry.last_emitted = now;
                    entry.repeats = 0;
                    Decision::Emit
                }
            }
            None => {
                self.entries.insert(
                    signature.to_string(),
                    DedupEntry {
                        last_emitted: now,
                        last_seen: now,
                        repeats: 0,
                        detection: finding.detection,
                        severity: finding.severity,
                        title: finding.title.clone(),
                    },
                );
                Decision::Emit
            }
        }
    }

    /// Close expired windows: emit one summary per signature that repeated, and
    /// prune long-idle entries.
    pub fn tick(&mut self, now: DateTime<Utc>) -> Vec<Finding> {
        let window = self.window;
        let mut summaries = Vec::new();
        for (sig, e) in self.entries.iter_mut() {
            if e.repeats > 0 && now - e.last_emitted >= window {
                // Only actionable patterns earn a summary: knowing a HIGH kept
                // recurring matters, knowing an INFO did is noise. Summaries are
                // LOW so they are logged distinctly but never page.
                if !e.severity.is_actionable() {
                    e.repeats = 0;
                    continue;
                }
                let severity = Severity::Low;
                summaries.push(
                    Finding::new(
                        e.detection,
                        severity,
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
                        "Identical detections from the same source are deduplicated so one \
                         incident produces one notification. This summary closes the window.",
                    ),
                );
                e.repeats = 0;
            }
        }
        let cutoff = now - window * RETENTION_WINDOWS;
        self.entries.retain(|_, e| e.last_seen >= cutoff);
        summaries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
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
    fn idle_entries_are_pruned() {
        let t0 = Utc::now();
        let mut d = Deduper::new(300);
        d.record("a", t0, &finding("a", Severity::Info));
        assert_eq!(d.len(), 1);
        d.tick(t0 + Duration::seconds(300 * 13));
        assert!(d.is_empty());
    }
}
