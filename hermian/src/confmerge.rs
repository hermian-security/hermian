use std::collections::HashSet;

fn header(line: &str) -> Option<String> {
    let t = line.trim();
    if t.starts_with("[[") || !t.starts_with('[') {
        return None;
    }
    let end = t.find(']')?;
    let rest = t[end + 1..].trim();
    if !rest.is_empty() && !rest.starts_with('#') {
        return None;
    }
    Some(t[1..end].trim().to_string())
}

fn any_header(line: &str) -> bool {
    line.trim_start().starts_with('[')
}

fn active_key(line: &str) -> Option<String> {
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with('[') {
        return None;
    }
    let (k, _) = t.split_once('=')?;
    let k = k.trim();
    is_ident(k).then(|| k.to_string())
}

fn commented_key(line: &str) -> Option<String> {
    let t = line.trim_start().strip_prefix('#')?;
    if t.starts_with('#') {
        return None;
    }
    let t = t.trim_start();
    let (k, _) = t.split_once('=')?;
    let k = k.trim();
    is_ident(k).then(|| k.to_string())
}

fn is_ident(k: &str) -> bool {
    !k.is_empty()
        && k.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

struct TemplateKey {
    key: String,
    comments: Vec<String>,
    line: String,
}

struct TemplateSection {
    path: String,
    intro: Vec<String>,
    keys: Vec<TemplateKey>,
}

fn parse_template(t: &str) -> Vec<TemplateSection> {
    let mut out: Vec<TemplateSection> = Vec::new();
    let mut pending: Vec<String> = Vec::new();
    for line in t.lines() {
        if let Some(path) = header(line) {
            out.push(TemplateSection {
                path,
                intro: Vec::new(),
                keys: Vec::new(),
            });
            pending.clear();
            continue;
        }
        let Some(sec) = out.last_mut() else {
            continue;
        };
        let optional = sec.path != "allowlist";
        if let Some(key) = active_key(line) {
            sec.keys.push(TemplateKey {
                key,
                comments: std::mem::take(&mut pending),
                line: line.to_string(),
            });
        } else if let Some(key) = commented_key(line).filter(|_| optional) {
            sec.keys.push(TemplateKey {
                key,
                comments: std::mem::take(&mut pending),
                line: line.to_string(),
            });
        } else if line.trim_start().starts_with('#') {
            if sec.keys.is_empty() {
                sec.intro.push(line.to_string());
            } else {
                pending.push(line.to_string());
            }
        } else if line.trim().is_empty() && !sec.keys.is_empty() {
            pending.clear();
        }
    }
    out
}

fn comment_out(line: &str) -> String {
    if line.trim_start().starts_with('#') || line.trim().is_empty() {
        line.to_string()
    } else {
        format!("#{}", line)
    }
}

fn section_body(lines: &[String], path: &str) -> Option<(usize, usize)> {
    let h = lines
        .iter()
        .position(|l| header(l).as_deref() == Some(path))?;
    let end = lines[h + 1..]
        .iter()
        .position(|l| any_header(l))
        .map(|i| h + 1 + i)
        .unwrap_or(lines.len());
    Some((h + 1, end))
}

pub const RETIRED: &[(&str, &str)] = &[
    ("general", "log_level"),
    ("ssh", "off_hours_start"),
    ("ssh", "off_hours_end"),
    ("ssh", "brute_digest_hours"),
];

pub fn retire(user: &str) -> Option<String> {
    let mut expected: toml::Value = toml::from_str(user).ok()?;
    let mut lines: Vec<String> = user.lines().map(str::to_string).collect();
    let mut changed = false;
    for (section, key) in RETIRED {
        let Some((start, end)) = section_body(&lines, section) else {
            continue;
        };
        for l in &mut lines[start..end] {
            if active_key(l).as_deref() == Some(*key) {
                *l = format!("#{}   # no longer used; safe to delete", l.trim_end());
                changed = true;
            }
        }
        if let Some(t) = expected.get_mut(*section).and_then(|v| v.as_table_mut()) {
            t.remove(*key);
        }
    }
    if !changed {
        return None;
    }
    let mut out = lines.join("\n");
    out.push('\n');
    let after: toml::Value = toml::from_str(&out).ok()?;
    (after == expected).then_some(out)
}

pub fn merge(user: &str, template: &str, version: &str) -> Option<String> {
    let before: toml::Value = toml::from_str(user).ok()?;
    let mut lines: Vec<String> = user.lines().map(str::to_string).collect();
    let mut appended: Vec<String> = Vec::new();
    let mut inserts: Vec<(usize, Vec<String>)> = Vec::new();

    for sec in parse_template(template) {
        let marker = format!("#[{}]", sec.path);
        let old_marker = format!("# [{}]", sec.path);
        let has_marker = lines
            .iter()
            .any(|l| l.trim() == marker || l.trim() == old_marker);
        let body = section_body(&lines, &sec.path);
        match body {
            Some((start, end)) => {
                let present: HashSet<String> = lines[start..end]
                    .iter()
                    .filter_map(|l| active_key(l).or_else(|| commented_key(l)))
                    .collect();
                let mut add: Vec<String> = Vec::new();
                for k in &sec.keys {
                    if present.contains(&k.key) {
                        continue;
                    }
                    add.extend(k.comments.iter().cloned());
                    add.push(comment_out(&k.line));
                }
                if add.is_empty() {
                    continue;
                }
                let mut at = end;
                while at > start && lines[at - 1].trim().is_empty() {
                    at -= 1;
                }
                let mut block = vec![format!(
                    "## New in {}: remove the # from a setting to turn it on.",
                    version
                )];
                block.extend(add);
                inserts.push((at, block));
            }
            None if has_marker => {}
            None => {
                appended.push(String::new());
                appended.push(marker);
                appended.extend(sec.intro.iter().cloned());
                for k in &sec.keys {
                    appended.extend(k.comments.iter().cloned());
                    appended.push(comment_out(&k.line));
                }
            }
        }
    }
    if inserts.is_empty() && appended.is_empty() {
        return None;
    }
    inserts.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    for (at, block) in inserts {
        for (i, l) in block.into_iter().enumerate() {
            lines.insert(at + i, l);
        }
    }
    if !appended.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "## ---- Added by 'hermian enable' ({}): sections this file didn't have. ----",
            version
        ));
        lines.push(
            "## Nothing below is on. To use a section, remove the # from its header and its \
             settings."
                .into(),
        );
        lines.extend(appended);
    }
    let mut out = lines.join("\n");
    out.push('\n');
    let after: toml::Value = toml::from_str(&out).ok()?;
    (after == before).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermian_core::{Config, DEFAULT_CONFIG_TOML};

    const BETA2: &str = "[general]\nhostname = \"\"\n\n[ssh]\npermit_root = false\nfailed_burst_count = 5\n\n\
                         [notifications]\nchannels = [\"journald\", \"file\"]\nmin_severity = \"HIGH\"\n\n\
                         [notifications.webhook]\nurl = \"\"\n\n[response]\nauto_isolate = false\nmanagement_cidrs = []\n\n[allowlist]\n";

    #[test]
    fn old_configs_get_the_missing_parts_commented_out() {
        let out = merge(BETA2, DEFAULT_CONFIG_TOML, "0.1.0-beta.6").expect("something to add");
        let a: toml::Value = toml::from_str(BETA2).unwrap();
        let b: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(a, b);
        assert!(out.contains("#[notifications.telegram]"), "{}", out);
        assert!(out.contains("#bot_token = \"\""));
        assert!(out.contains("#allowed_user_ids = []"));
        assert!(out.contains("#[notifications.email]"));
        assert!(out.contains("#[detections]"));
        let resp = out.find("[response]").unwrap();
        let block = out.find("#block_duration_hours = 24").unwrap();
        let allow = out.find("[allowlist]").unwrap();
        assert!(resp < block && block < allow, "{}", out);
        let ssh = out.find("[ssh]").unwrap();
        let digest = out.find("#brute_digest_days = 7").unwrap();
        assert!(ssh < digest && digest < out.find("[notifications]").unwrap());
        assert!(out.contains("#message_thread_id = 12345"));
        Config::parse(&out).unwrap().validate().unwrap();
    }

    #[test]
    fn running_twice_changes_nothing() {
        let once = merge(BETA2, DEFAULT_CONFIG_TOML, "v").unwrap();
        assert!(merge(&once, DEFAULT_CONFIG_TOML, "v").is_none(), "{}", once);
    }

    #[test]
    fn a_current_config_is_left_alone() {
        assert!(merge(DEFAULT_CONFIG_TOML, DEFAULT_CONFIG_TOML, "v").is_none());
    }

    #[test]
    fn values_are_never_touched() {
        let user = "[notifications]\nchannels = [\"journald\", \"telegram\"]\n\n\
                    [notifications.telegram]\nbot_token = \"1:secret\"\nchat_id = \"42\"\n";
        let out = merge(user, DEFAULT_CONFIG_TOML, "v").unwrap();
        assert!(out.contains("bot_token = \"1:secret\""));
        assert!(!out.contains("#bot_token"), "set keys aren't added again");
        assert!(out.contains("#actions = false"));
        let a: toml::Value = toml::from_str(user).unwrap();
        assert_eq!(a, toml::from_str::<toml::Value>(&out).unwrap());
    }

    #[test]
    fn broken_files_are_not_touched() {
        assert!(merge("[general\nhostname = ", DEFAULT_CONFIG_TOML, "v").is_none());
    }

    const WITH_RETIRED: &str = "[general]\nhostname = \"web-01\"\nlog_level = \"info\"\n\n\
                                [ssh]\npermit_root = false\n\
                                off_hours_start = 22    # UTC; set start == end to disable off-hours weighting\n\
                                off_hours_end = 6\n\
                                failed_burst_count = 7\n";

    #[test]
    fn retired_settings_are_commented_out_and_nothing_else_moves() {
        let out = retire(WITH_RETIRED).expect("retired keys present");
        for key in ["log_level", "off_hours_start", "off_hours_end"] {
            let line = out
                .lines()
                .find(|l| l.contains(key))
                .unwrap_or_else(|| panic!("{} gone entirely", key));
            assert!(
                line.starts_with('#') && line.ends_with("safe to delete"),
                "{}",
                line
            );
        }
        let cfg = Config::parse(&out).unwrap();
        assert_eq!(cfg.general.hostname, "web-01");
        assert_eq!(cfg.ssh.failed_burst_count, 7);
        assert!(retire(&out).is_none());
        assert!(retire(DEFAULT_CONFIG_TOML).is_none());
        assert!(retire("[general\nbroken").is_none());
    }

    #[test]
    fn retire_only_touches_the_right_section() {
        let t = "[ssh]\noff_hours_start = 22\n\n[notifications.webhook]\nurl = \"\"\n";
        let out = retire(t).unwrap();
        assert!(out.contains("#off_hours_start = 22"));
        assert!(out.contains("url = \"\""));
    }

    #[test]
    fn retire_then_merge_still_loads() {
        let retired = retire(WITH_RETIRED).unwrap();
        let merged = merge(&retired, DEFAULT_CONFIG_TOML, "v-test").unwrap_or(retired);
        let cfg = Config::parse(&merged).unwrap();
        assert_eq!(cfg.general.hostname, "web-01");
        assert_eq!(cfg.ssh.failed_burst_count, 7);
        assert!(!merged
            .lines()
            .any(|l| l.trim_start().starts_with("log_level")));
    }

    #[test]
    fn added_lines_are_explanations_or_settings() {
        let out = merge(BETA2, DEFAULT_CONFIG_TOML, "v").unwrap();
        let before: Vec<&str> = BETA2.lines().collect();
        for l in out.lines().filter(|l| !before.contains(l)) {
            let t = l.trim_start();
            if !t.starts_with('#') {
                continue;
            }
            assert!(
                t.starts_with("##") || !t[1..].starts_with(' '),
                "neither ## nor #setting: {:?}",
                l
            );
        }
        assert!(!out.contains("# #"), "doubled comment marker:\n{}", out);
        let old = format!("{}\n# [notifications.webhook]\n# url = \"\"\n", BETA2);
        let again = merge(&old, DEFAULT_CONFIG_TOML, "v").unwrap();
        assert!(!again.contains("#[notifications.webhook]"), "{}", again);
    }
}
