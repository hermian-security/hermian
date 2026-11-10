use hermian_core::snapmount;
use sha3::{Digest, Sha3_384};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const UNIT_DIR: &str = "/etc/systemd/system";
const ASSERTS: &str = "/var/lib/snapd/assertions/asserts-v0";
const LINK_DIRS: &[&str] = &["multi-user.target.wants", "snapd.mounts.target.wants"];

pub fn store_signed_mount(path: &str) -> bool {
    check(Path::new("/"), path, (0, 0)).is_some()
}

fn under(root: &Path, abs: &str) -> PathBuf {
    root.join(abs.trim_start_matches('/'))
}

fn trusted(meta: &fs::Metadata, (uid, gid): (u32, u32)) -> bool {
    meta.file_type().is_file()
        && meta.uid() == uid
        && meta.mode() & 0o002 == 0
        && (meta.mode() & 0o020 == 0 || meta.gid() == gid)
}

fn check(root: &Path, path: &str, owner: (u32, u32)) -> Option<()> {
    let rest = path.strip_prefix(UNIT_DIR)?.strip_prefix('/')?;
    let name = match rest.split_once('/') {
        Some((dir, n)) if LINK_DIRS.contains(&dir) => {
            let target = fs::read_link(under(root, path)).ok()?;
            if target != Path::new(UNIT_DIR).join(n) {
                return None;
            }
            n
        }
        Some(_) => return None,
        None => rest,
    };
    if name.contains('/') || !name.ends_with(".mount") {
        return None;
    }
    let unit = under(root, &format!("{}/{}", UNIT_DIR, name));
    let meta = fs::symlink_metadata(&unit).ok()?;
    if !trusted(&meta, owner) || meta.len() > 4096 {
        return None;
    }
    let mount = snapmount::parse(name, &fs::read_to_string(&unit).ok()?)?;

    let blob = under(root, &mount.snap_file);
    if !trusted(&fs::symlink_metadata(&blob).ok()?, owner) {
        return None;
    }
    let digest = sha3_384_b64url(&blob)?;

    let asserts = under(root, ASSERTS);
    let rev_text = active(&asserts.join("snap-revision").join(&digest), owner)?;
    let rev = headers(&rev_text);
    if field(&rev, "type") != Some("snap-revision")
        || field(&rev, "snap-sha3-384") != Some(digest.as_str())
        || field(&rev, "snap-revision") != Some(mount.revision.to_string().as_str())
    {
        return None;
    }
    let snap_id = field(&rev, "snap-id")?;
    if snap_id.is_empty() || !snap_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let decl_text = active(
        &asserts.join("snap-declaration").join("16").join(snap_id),
        owner,
    )?;
    let decl = headers(&decl_text);
    let snap_name = mount.instance.split('_').next()?;
    (field(&decl, "type") == Some("snap-declaration")
        && field(&decl, "snap-id") == Some(snap_id)
        && field(&decl, "snap-name") == Some(snap_name))
    .then_some(())
}

fn sha3_384_b64url(path: &Path) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let mut h = Sha3_384::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(b64url(&h.finalize()))
}

fn b64url(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn active(dir: &Path, owner: (u32, u32)) -> Option<String> {
    let mut best: Option<(u32, PathBuf)> = None;
    for e in fs::read_dir(dir).ok()?.flatten() {
        let name = e.file_name();
        let name = name.to_str()?;
        let format = match name.strip_prefix("active") {
            Some("") => 0,
            Some(n) => match n.strip_prefix('.').and_then(|d| d.parse().ok()) {
                Some(d) => d,
                None => continue,
            },
            None => continue,
        };
        if best.as_ref().is_none_or(|(f, _)| format > *f) {
            best = Some((format, e.path()));
        }
    }
    let path = best?.1;
    let meta = fs::symlink_metadata(&path).ok()?;
    if !trusted(&meta, owner) || meta.len() > 64 * 1024 {
        return None;
    }
    fs::read_to_string(path).ok()
}

fn headers(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .take_while(|l| !l.is_empty())
        .filter(|l| !l.starts_with(' '))
        .filter_map(|l| l.split_once(": "))
        .collect()
}

fn field<'a>(h: &[(&str, &'a str)], key: &str) -> Option<&'a str> {
    let mut it = h.iter().filter(|(k, _)| *k == key);
    let v = it.next()?.1;
    it.next().is_none().then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const UNIT: &str = "[Unit]\nDescription=Mount unit for snapd, revision 28332\nAfter=snapd.mounts-pre.target\nBefore=snapd.mounts.target\n\n[Mount]\nWhat=/var/lib/snapd/snaps/snapd_28332.snap\nWhere=/snap/snapd/28332\nType=squashfs\nOptions=nodev,ro,x-gdu.hide,x-gvfs-hide\nLazyUnmount=yes\n\n[Install]\nWantedBy=snapd.mounts.target\nWantedBy=multi-user.target\n";
    const SNAP_ID: &str = "PMrrV4ml8uWuEUDBT8dSGnKUYbevVhc4";

    struct Host {
        root: PathBuf,
        owner: (u32, u32),
    }

    impl Host {
        fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("hermian-snapd-{}-{}", tag, std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let h = Host {
                root,
                owner: unsafe { (libc::geteuid(), libc::getegid()) },
            };
            h.write("/etc/systemd/system/snap-snapd-28332.mount", UNIT);
            h.write(
                "/var/lib/snapd/snaps/snapd_28332.snap",
                "hsqs pretend squashfs",
            );
            let d = h.digest();
            h.write(
                &format!("{}/snap-revision/{}/active", ASSERTS, d),
                &format!(
                    "type: snap-revision\nauthority-id: canonical\nsnap-sha3-384: {}\nsnap-id: {}\nsnap-size: 21\nsnap-revision: 28332\ndeveloper-id: canonical\n\nAcLBXAQAAQoABgUC\n",
                    d, SNAP_ID
                ),
            );
            h.write(
                &format!("{}/snap-declaration/16/{}/active", ASSERTS, SNAP_ID),
                &format!(
                    "type: snap-declaration\nauthority-id: canonical\nseries: 16\nsnap-id: {}\nsnap-name: snapd\npublisher-id: canonical\n\nAcLBXAQAAQoABgUC\n",
                    SNAP_ID
                ),
            );
            h
        }
        fn p(&self, abs: &str) -> PathBuf {
            under(&self.root, abs)
        }
        fn write(&self, abs: &str, s: &str) {
            let p = self.p(abs);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, s).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        }
        fn digest(&self) -> String {
            sha3_384_b64url(&self.p("/var/lib/snapd/snaps/snapd_28332.snap")).unwrap()
        }
        fn link(&self, abs: &str, target: &str) {
            let p = self.p(abs);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            symlink(target, p).unwrap();
        }
        fn ok(&self, path: &str) -> bool {
            check(&self.root, path, self.owner).is_some()
        }
    }

    impl Drop for Host {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    const UNIT_PATH: &str = "/etc/systemd/system/snap-snapd-28332.mount";
    const LINK_PATH: &str = "/etc/systemd/system/multi-user.target.wants/snap-snapd-28332.mount";

    #[test]
    fn b64url_matches_known_vectors() {
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
        let h = Sha3_384::digest(b"");
        assert_eq!(
            b64url(&h),
            "DGOnW4ReT30BEH2FLkwkhcUaUKqqlPxhmV5xu-6YOirDcTgxJkrbR_tr0eBY1fAE"
        );
    }

    #[test]
    fn store_signed_refresh_is_vouched() {
        let h = Host::new("ok");
        assert!(h.ok(UNIT_PATH));
        h.link(LINK_PATH, "/etc/systemd/system/snap-snapd-28332.mount");
        assert!(h.ok(LINK_PATH));
    }

    #[test]
    fn swapped_snap_file_is_not_vouched() {
        let h = Host::new("swap");
        h.write("/var/lib/snapd/snaps/snapd_28332.snap", "attacker squashfs");
        assert!(!h.ok(UNIT_PATH));
    }

    #[test]
    fn unasserted_snap_is_not_vouched() {
        let h = Host::new("dangerous");
        fs::remove_dir_all(h.p(&format!("{}/snap-revision", ASSERTS))).unwrap();
        assert!(!h.ok(UNIT_PATH));
    }

    #[test]
    fn assertion_for_another_revision_or_snap_is_not_vouched() {
        let h = Host::new("rev");
        let d = h.digest();
        let p = format!("{}/snap-revision/{}/active", ASSERTS, d);
        let orig = fs::read_to_string(h.p(&p)).unwrap();
        h.write(
            &p,
            &orig.replace("snap-revision: 28332", "snap-revision: 1"),
        );
        assert!(!h.ok(UNIT_PATH));
        h.write(&p, &orig);
        assert!(h.ok(UNIT_PATH));
        h.write(
            &format!("{}/snap-declaration/16/{}/active", ASSERTS, SNAP_ID),
            &format!(
                "type: snap-declaration\nsnap-id: {}\nsnap-name: core\n\n",
                SNAP_ID
            ),
        );
        assert!(!h.ok(UNIT_PATH));
    }

    #[test]
    fn duplicate_headers_are_not_trusted() {
        let h = Host::new("dup");
        let p = format!("{}/snap-revision/{}/active", ASSERTS, h.digest());
        let orig = fs::read_to_string(h.p(&p)).unwrap();
        h.write(
            &p,
            &orig.replace(
                "snap-revision: 28332\n",
                "snap-revision: 28332\nsnap-revision: 1\n",
            ),
        );
        assert!(!h.ok(UNIT_PATH));
    }

    #[test]
    fn links_must_point_at_the_unit_of_the_same_name() {
        let h = Host::new("link");
        h.link(LINK_PATH, "/tmp/snap-snapd-28332.mount");
        assert!(!h.ok(LINK_PATH));
        let other = "/etc/systemd/system/snapd.mounts.target.wants/snap-snapd-28332.mount";
        h.link(other, "snap-snapd-28332.mount");
        assert!(!h.ok(other));
        let getty = "/etc/systemd/system/getty.target.wants/snap-snapd-28332.mount";
        h.link(getty, "/etc/systemd/system/snap-snapd-28332.mount");
        assert!(!h.ok(getty));
    }

    #[test]
    fn writable_or_linked_files_are_not_trusted() {
        let h = Host::new("perm");
        fs::set_permissions(h.p(UNIT_PATH), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!h.ok(UNIT_PATH));
        fs::set_permissions(h.p(UNIT_PATH), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(h.ok(UNIT_PATH));
        let snap = h.p("/var/lib/snapd/snaps/snapd_28332.snap");
        let real = h.p("/var/lib/snapd/snaps/real.snap");
        fs::rename(&snap, &real).unwrap();
        symlink(&real, &snap).unwrap();
        assert!(!h.ok(UNIT_PATH));
    }

    #[test]
    fn wrong_owner_is_not_trusted() {
        let h = Host::new("owner");
        assert!(check(&h.root, UNIT_PATH, (h.owner.0 + 1, h.owner.1)).is_none());
    }

    #[test]
    fn group_write_only_from_the_owning_group() {
        let h = Host::new("group");
        let a = h.p(&format!("{}/snap-revision/{}/active", ASSERTS, h.digest()));
        fs::set_permissions(&a, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(h.ok(UNIT_PATH));
        assert!(check(&h.root, UNIT_PATH, (h.owner.0, h.owner.1 + 1)).is_none());
        fs::set_permissions(&a, fs::Permissions::from_mode(0o646)).unwrap();
        assert!(!h.ok(UNIT_PATH));
    }

    #[test]
    #[ignore]
    fn this_hosts_snap_mounts_are_vouched() {
        let mut seen = 0;
        for dir in ["", "/multi-user.target.wants", "/snapd.mounts.target.wants"] {
            let Ok(entries) = fs::read_dir(format!("{}{}", UNIT_DIR, dir)) else {
                continue;
            };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with("snap-") && name.ends_with(".mount") {
                    let path = format!("{}{}/{}", UNIT_DIR, dir, name);
                    assert!(store_signed_mount(&path), "{} not vouched", path);
                    seen += 1;
                }
            }
        }
        assert!(seen > 0, "no snap mount units on this host");
        eprintln!("{} snap mount units vouched", seen);
    }

    #[test]
    fn non_snap_units_are_ignored() {
        let h = Host::new("other");
        h.write("/etc/systemd/system/evil.service", UNIT);
        assert!(!h.ok("/etc/systemd/system/evil.service"));
        assert!(!h.ok("/etc/cron.d/snap-snapd-28332.mount"));
    }
}
