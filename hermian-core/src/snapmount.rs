#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapMount {
    pub instance: String,
    pub revision: u64,
    pub snap_file: String,
}

const MOUNT_ROOTS: &[&str] = &["/snap", "/var/lib/snapd/snap"];
const BLOB_DIR: &str = "/var/lib/snapd/snaps";

pub fn parse(unit_name: &str, content: &str) -> Option<SnapMount> {
    let mut section = "";
    let mut description = None;
    let mut what = None;
    let mut where_ = None;
    let mut fstype = None;
    let mut options = None;
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = match line {
                "[Unit]" | "[Mount]" | "[Install]" => line,
                _ => return None,
            };
            continue;
        }
        let (k, v) = line.split_once('=')?;
        let ok = match (section, k) {
            ("[Unit]", "Description") => set_once(&mut description, v),
            ("[Unit]", "After") => v == "snapd.mounts-pre.target",
            ("[Unit]", "Before") => matches!(
                v,
                "snapd.mounts.target"
                    | "local-fs.target"
                    | "systemd-udevd.service systemd-modules-load.service"
                    | "usr-lib-modules.mount usr-lib-firmware.mount"
            ),
            ("[Mount]", "What") => set_once(&mut what, v),
            ("[Mount]", "Where") => set_once(&mut where_, v),
            ("[Mount]", "Type") => set_once(&mut fstype, v),
            ("[Mount]", "Options") => set_once(&mut options, v),
            ("[Mount]", "LazyUnmount") => v == "yes",
            ("[Install]", "WantedBy") => {
                matches!(v, "snapd.mounts.target" | "multi-user.target")
            }
            _ => false,
        };
        if !ok {
            return None;
        }
    }
    let where_ = where_?;
    let (root, rest) = MOUNT_ROOTS
        .iter()
        .find_map(|r| Some((*r, where_.strip_prefix(r)?.strip_prefix('/')?)))?;
    let (instance, rev) = rest.split_once('/')?;
    if !valid_instance(instance) || !valid_revision(rev) {
        return None;
    }
    let snap_file = format!("{}/{}_{}.snap", BLOB_DIR, instance, rev);
    if what? != snap_file
        || description? != format!("Mount unit for {}, revision {}", instance, rev)
        || !matches!(fstype?, "squashfs" | "fuse.squashfuse" | "fuse.snapfuse")
        || !valid_options(options?)
        || unit_name
            != format!(
                "{}.mount",
                escape_path(&format!("{}/{}/{}", root, instance, rev))
            )
    {
        return None;
    }
    Some(SnapMount {
        instance: instance.to_string(),
        revision: rev.parse().ok()?,
        snap_file,
    })
}

fn set_once<'a>(slot: &mut Option<&'a str>, v: &'a str) -> bool {
    slot.replace(v).is_none()
}

fn valid_options(opts: &str) -> bool {
    let list: Vec<&str> = opts.split(',').collect();
    list.contains(&"nodev")
        && list.contains(&"ro")
        && list.iter().all(|o| {
            matches!(
                *o,
                "nodev" | "ro" | "x-gdu.hide" | "x-gvfs-hide" | "allow_other"
            ) || o.strip_prefix("context=").is_some_and(|c| {
                !c.is_empty()
                    && c.chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || "_:.\"-".contains(ch))
            })
        })
}

pub fn valid_instance(s: &str) -> bool {
    let (name, key) = match s.split_once('_') {
        Some((n, k)) => (n, Some(k)),
        None => (s, None),
    };
    let name_ok = (1..=40).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && name.chars().any(|c| c.is_ascii_lowercase())
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--");
    let key_ok = key.is_none_or(|k| {
        (1..=10).contains(&k.len())
            && k.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    });
    name_ok && key_ok
}

fn valid_revision(s: &str) -> bool {
    !s.is_empty() && s.len() <= 12 && !s.starts_with('0') && s.chars().all(|c| c.is_ascii_digit())
}

fn escape_path(path: &str) -> String {
    let mut out = String::new();
    for (i, c) in path.trim_start_matches('/').chars().enumerate() {
        match c {
            '/' => out.push('-'),
            '.' if i == 0 => out.push_str("\\x2e"),
            c if c.is_ascii_alphanumeric() || c == ':' || c == '_' || c == '.' => out.push(c),
            c => out.push_str(&format!("\\x{:02x}", c as u32)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str, rev: &str) -> String {
        format!(
            "[Unit]\nDescription=Mount unit for {n}, revision {r}\nAfter=snapd.mounts-pre.target\nBefore=snapd.mounts.target\n\n[Mount]\nWhat=/var/lib/snapd/snaps/{n}_{r}.snap\nWhere=/snap/{n}/{r}\nType=squashfs\nOptions=nodev,ro,x-gdu.hide,x-gvfs-hide\nLazyUnmount=yes\n\n[Install]\nWantedBy=snapd.mounts.target\nWantedBy=multi-user.target\n",
            n = name,
            r = rev
        )
    }

    #[test]
    fn snapd_unit_parses() {
        let m = parse("snap-snapd-28332.mount", &unit("snapd", "28332")).unwrap();
        assert_eq!(m.instance, "snapd");
        assert_eq!(m.revision, 28332);
        assert_eq!(m.snap_file, "/var/lib/snapd/snaps/snapd_28332.snap");
    }

    #[test]
    fn dashes_and_instance_keys_are_escaped_like_systemd() {
        let c = unit("google-cloud-cli", "412");
        assert!(parse("snap-google\\x2dcloud\\x2dcli-412.mount", &c).is_some());
        assert!(parse("snap-google-cloud-cli-412.mount", &c).is_none());
        let c = unit("lxd_dev", "7");
        assert!(parse("snap-lxd_dev-7.mount", &c).is_some());
    }

    #[test]
    fn fuse_selinux_and_older_snapd_layouts_parse() {
        let c = unit("core22", "1663").replace(
            "Type=squashfs\nOptions=nodev,ro,x-gdu.hide,x-gvfs-hide",
            "Type=fuse.squashfuse\nOptions=nodev,context=system_u:object_r:snappy_snap_t:s0,ro,x-gdu.hide,x-gvfs-hide,allow_other",
        );
        assert!(parse("snap-core22-1663.mount", &c).is_some());
        let old = unit("core22", "1663").replace("After=snapd.mounts-pre.target\n", "");
        assert!(parse("snap-core22-1663.mount", &old).is_some());
    }

    #[test]
    fn anything_that_runs_code_is_refused() {
        let base = unit("snapd", "28332");
        for extra in [
            "[Service]\nExecStart=/tmp/x\n",
            "[Mount]\nExecStartPre=/tmp/x\n",
            "[Unit]\nOnSuccess=evil.service\n",
            "[Unit]\nRequires=evil.service\n",
            "[Install]\nAlso=evil.service\n",
            "[Install]\nWantedBy=evil.target\n",
            "[Mount]\nDirectoryMode=0777\n",
            "# hello\n",
            " [Unit]\n",
        ] {
            let c = format!("{}{}", base, extra);
            assert!(parse("snap-snapd-28332.mount", &c).is_none(), "{:?}", extra);
        }
    }

    #[test]
    fn mount_anywhere_else_is_refused() {
        let base = unit("snapd", "28332");
        let cases = [
            base.replace("Where=/snap/snapd/28332", "Where=/usr/bin"),
            base.replace(
                "Where=/snap/snapd/28332",
                "Where=/snap/snapd/../../usr/28332",
            ),
            base.replace(
                "What=/var/lib/snapd/snaps/snapd_28332.snap",
                "What=/tmp/snapd_28332.snap",
            ),
            base.replace(
                "What=/var/lib/snapd/snaps/snapd_28332.snap",
                "What=/var/lib/snapd/snaps/core_28332.snap",
            ),
            base.replace("nodev,ro,", "ro,"),
            base.replace("nodev,ro,", "nodev,"),
            base.replace("x-gvfs-hide", "x-gvfs-hide,suid"),
            base.replace("x-gvfs-hide", "x-gvfs-hide,exec"),
            base.replace("Type=squashfs", "Type=none"),
            base.replace("Options=nodev", "Options=bind,nodev"),
            base.replace("revision 28332", "revision 1"),
            base.replace(
                "Where=/snap/snapd/28332\n",
                "Where=/snap/snapd/28332\nWhere=/usr/bin\n",
            ),
        ];
        for c in cases {
            assert!(parse("snap-snapd-28332.mount", &c).is_none(), "{}", c);
        }
    }

    #[test]
    fn unit_name_must_match_the_mount_point() {
        let c = unit("snapd", "28332");
        assert!(parse("snap-snapd-28331.mount", &c).is_none());
        assert!(parse("ssh.mount", &c).is_none());
        assert!(parse("snap-snapd-28332.service", &c).is_none());
    }

    #[test]
    fn local_and_odd_revisions_are_refused() {
        for (n, r) in [
            ("snapd", "x1"),
            ("snapd", "0"),
            ("snapd", "01"),
            ("snapd", "-1"),
        ] {
            let name = format!("snap-{}-{}.mount", n, r.replace('-', "\\x2d"));
            assert!(parse(&name, &unit(n, r)).is_none(), "{}", r);
        }
    }

    #[test]
    fn instance_names() {
        for ok in ["snapd", "core22", "lxd_dev", "a1"] {
            assert!(valid_instance(ok), "{}", ok);
        }
        for bad in [
            "", "-a", "a-", "a--b", "123", "A", "a/b", "a_", "a_KEY", "a..b",
        ] {
            assert!(!valid_instance(bad), "{}", bad);
        }
    }
}
