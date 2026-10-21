//! Bring an existing config.toml up to date with the template, as comments.
//!
//! A fresh install gets the full template, but upgrades never touch an
//! existing file, so new settings (and whole sections, like Telegram for
//! configs written by early betas) were invisible to users. This adds
//! whatever the file lacks, *switched off*, next to where it belongs:
//!
//! - a missing setting goes at the end of its section, with its comments;
//! - a missing section goes at the end of the file.
//!
//! Added lines follow the template's convention: explanations keep their
//! `##`, settings get a single `#` with no space (`#key = value`), so
//! removing one `#` from any added line either turns a setting on or leaves
//! a comment, never a broken file.
//!
//! Nothing active changes: the result must parse to exactly the same values
//! as the original, or nothing is written. Settings already present (even
//! commented out) aren't added again, so running it twice is a no-op.

use std::collections::HashSet;

/// An uncommented `[table]` header (not `[[array]]`), as a dotted path.
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

/// Any active header line, including `[[array]]`: it ends the section above.
fn any_header(line: &str) -> bool {
    line.trim_start().starts_with('[')
}

/// `key` from an active `key = value` line.
fn active_key(line: &str) -> Option<String> {
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with('[') {
        return None;
    }
    let (k, _) = t.split_once('=')?;
    let k = k.trim();
    is_ident(k).then(|| k.to_string())
}

/// `key` from a switched-off `#key = value` line (or `# key = value`, as
/// older versions wrote them). Not from `##` explanations.
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

/// One setting from the template: its key, the comment lines that explain
/// it, and the line itself (already commented if it's optional).
struct TemplateKey {
    key: String,
    comments: Vec<String>,
    line: String,
}

struct TemplateSection {
    path: String,
    /// Comment lines right under the header, before the first setting.
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
            continue; // file preamble
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
        } else if line.trim().is_empty() {
            // A blank line separates explanations from what follows.
            if !sec.keys.is_empty() {
                pending.clear();
            }
        }
    }
    out
}

/// A template line, switched off: settings and headers get one `#`;
/// explanations (`##`) and settings already off stay as they are.
fn comment_out(line: &str) -> String {
    if line.trim_start().starts_with('#') || line.trim().is_empty() {
        line.to_string()
    } else {
        format!("#{}", line)
    }
}

/// Index range `[start, end)` of section `path`'s body in `lines` (after its
/// header, up to the next header), if it has an explicit header.
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

/// Settings Hermian no longer reads, as (section, key). Old configs still
/// load (the parser accepts them and ignores them); `retire` comments them
/// out so nobody tunes a setting that does nothing. They stop being
/// accepted at v0.1.0.
pub const RETIRED: &[(&str, &str)] = &[
    ("general", "log_level"),
    ("ssh", "off_hours_start"),
    ("ssh", "off_hours_end"),
    // Weekly now: ssh.brute_digest_days.
    ("ssh", "brute_digest_hours"),
];

/// The user's file with every retired setting commented out, or `None` if
/// it has none (or it couldn't be done safely). Nothing else changes: the
/// result must parse to the original minus exactly those keys.
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

/// The user's file with everything the template has and it lacks added as
/// comments, or `None` if nothing is missing (or it couldn't be done safely).
pub fn merge(user: &str, template: &str, version: &str) -> Option<String> {
    let before: toml::Value = toml::from_str(user).ok()?;
    let mut lines: Vec<String> = user.lines().map(str::to_string).collect();
    let mut appended: Vec<String> = Vec::new();
    let mut inserts: Vec<(usize, Vec<String>)> = Vec::new();

    for sec in parse_template(template) {
        let marker = format!("#[{}]", sec.path);
        // Older versions wrote "# [section]".
        let old_marker = format!("# [{}]", sec.path);
        let has_marker = lines
            .iter()
            .any(|l| l.trim() == marker || l.trim() == old_marker);
        // A table defined only implicitly (e.g. `[notifications.telegram]`
        // with no `[notifications]` line) has no body to insert into; its
        // missing keys are appended under a commented header, which stays
        // valid TOML if uncommented.
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
                // After the section's last non-blank line.
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
    // Insert bottom-up so earlier indexes stay valid.
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
    // Comments only: the settings must read back exactly the same.
    let after: toml::Value = toml::from_str(&out).ok()?;
    (after == before).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermian_core::{Config, DEFAULT_CONFIG_TOML};

    /// Shape of the config beta.2 wrote (no Telegram, no email, no new keys).
    const BETA2: &str = "[general]\nhostname = \"\"\n\n[ssh]\npermit_root = false\nfailed_burst_count = 5\n\n\
                         [notifications]\nchannels = [\"journald\", \"file\"]\nmin_severity = \"HIGH\"\n\n\
                         [notifications.webhook]\nurl = \"\"\n\n[response]\nauto_isolate = false\nmanagement_cidrs = []\n\n[allowlist]\n";

    #[test]
    fn old_configs_get_the_missing_parts_commented_out() {
        let out = merge(BETA2, DEFAULT_CONFIG_TOML, "0.1.0-beta.6").expect("something to add");
        // Same settings as before.
        let a: toml::Value = toml::from_str(BETA2).unwrap();
        let b: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(a, b);
        // Whole sections, at the end.
        assert!(out.contains("#[notifications.telegram]"), "{}", out);
        assert!(out.contains("#bot_token = \"\""));
        assert!(out.contains("#allowed_user_ids = []"));
        assert!(out.contains("#[notifications.email]"));
        assert!(out.contains("#[detections]"));
        // Keys missing from existing sections, inside them.
        let resp = out.find("[response]").unwrap();
        let block = out.find("#block_duration_hours = 24").unwrap();
        let allow = out.find("[allowlist]").unwrap();
        assert!(resp < block && block < allow, "{}", out);
        let ssh = out.find("[ssh]").unwrap();
        let digest = out.find("#brute_digest_days = 7").unwrap();
        assert!(ssh < digest && digest < out.find("[notifications]").unwrap());
        // Optional settings that are only commented in the template too.
        assert!(out.contains("#message_thread_id = 12345"));
        // And the file still loads as a config.
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

    /// The shape configs had before #49: the retired keys set, in their
    /// sections, among settings that still matter.
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
        // Twice is a no-op, and a config without them isn't touched.
        assert!(retire(&out).is_none());
        assert!(retire(DEFAULT_CONFIG_TOML).is_none());
        assert!(retire("[general\nbroken").is_none());
    }

    /// Only the key in its own section: a same-named key elsewhere stays.
    #[test]
    fn retire_only_touches_the_right_section() {
        let t = "[ssh]\noff_hours_start = 22\n\n[notifications.webhook]\nurl = \"\"\n";
        let out = retire(t).unwrap();
        assert!(out.contains("#off_hours_start = 22"));
        assert!(out.contains("url = \"\""));
    }

    /// What `hermian enable` does: retire, then add what's new. The result
    /// still loads and keeps the user's values.
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

    /// What an upgrade adds follows the template's convention: removing one
    /// `#` from an added line turns a setting on or leaves a comment.
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
        // An older file's "# [section]" marker still counts as present.
        let old = format!("{}\n# [notifications.webhook]\n# url = \"\"\n", BETA2);
        let again = merge(&old, DEFAULT_CONFIG_TOML, "v").unwrap();
        assert!(!again.contains("#[notifications.webhook]"), "{}", again);
    }
}
