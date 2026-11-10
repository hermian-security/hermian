use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub static INOTIFY_OVERFLOWS: AtomicU64 = AtomicU64::new(0);
pub static AUDIT_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

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
        (
            "forged audit messages",
            crate::auditnetlink::SPOOFED.load(Ordering::Relaxed),
        ),
    ] {
        if v > 0 {
            out.insert(name.to_string(), v);
        }
    }
    out
}

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
