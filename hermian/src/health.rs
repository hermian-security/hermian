//! Counters for telemetry the kernel or a collector had to drop.
//!
//! Collectors bump these; the daemon reads them every tick, pages when one
//! grows, and shows the totals in `hermian status`. A fork/exec or file
//! flood that overflows a buffer is a cheap way to go unseen, so a loss must
//! reach the operator, not just the local log.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// inotify queue overflows (each one is followed by a rescan).
pub static INOTIFY_OVERFLOWS: AtomicU64 = AtomicU64::new(0);
/// Times the audit netlink socket reported ENOBUFS (records were lost).
pub static AUDIT_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

/// Totals since start, by source. Only non-zero ones are listed.
pub fn snapshot() -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for (name, v) in [
        (
            "ebpf events",
            crate::ebpf::LOST_EVENTS.load(Ordering::Relaxed),
        ),
        (
            "inotify overflows",
            INOTIFY_OVERFLOWS.load(Ordering::Relaxed),
        ),
        ("audit overflows", AUDIT_OVERFLOWS.load(Ordering::Relaxed)),
    ] {
        if v > 0 {
            out.insert(name.to_string(), v);
        }
    }
    out
}

/// Sources whose count grew between two snapshots, with the increase.
pub fn grown(before: &BTreeMap<String, u64>, now: &BTreeMap<String, u64>) -> Vec<(String, u64)> {
    now.iter()
        .filter_map(|(k, v)| {
            let old = before.get(k).copied().unwrap_or(0);
            (*v > old).then(|| (k.clone(), v - old))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_is_reported_per_source() {
        let a: BTreeMap<String, u64> = [("ebpf events".to_string(), 5)].into_iter().collect();
        let b: BTreeMap<String, u64> = [
            ("ebpf events".to_string(), 9),
            ("inotify overflows".to_string(), 1),
        ]
        .into_iter()
        .collect();
        let g = grown(&a, &b);
        assert_eq!(
            g,
            vec![
                ("ebpf events".to_string(), 4),
                ("inotify overflows".to_string(), 1)
            ]
        );
        assert!(grown(&b, &b).is_empty());
    }
}
