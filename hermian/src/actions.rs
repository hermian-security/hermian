//! Carrying out a response (a Telegram button, or its CLI twin) and saying
//! exactly what happened.
//!
//! Every result is one line per target, each marked:
//!   ✓  done: the change was made
//!   ·  already: it was that way, since when and by whom
//!   ⊘  refused: a safety rule stopped it, named
//!   ✗  failed: the cause in a sentence and the next step as a command
//! Short, plain sentences; never a raw error. The ledger remembers who did what, so a second press,
//! an undo after a CLI unblock, or a block that's already in place can say
//! so. See dist/RESPONSE-ACTIONS.md.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use anyhow::Result;
use chrono::{DateTime, Utc};
use hermian_core::{Config, ResponseAction};
use serde::{Deserialize, Serialize};

use crate::blocklist::{self, Blocked, NftError};
use crate::sessions::{self, DisconnectError, Disconnected};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mark {
    Done,
    Already,
    Refused,
    Failed,
    /// Not an outcome: what the person should know next.
    Note,
}

impl Mark {
    /// The sign a result line starts with (none for a note).
    pub fn sign(self) -> &'static str {
        match self {
            Mark::Done => "✓",
            Mark::Already => "·",
            Mark::Refused => "⊘",
            Mark::Failed => "✗",
            Mark::Note => "",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub mark: Mark,
    pub text: String,
}

impl Line {
    pub fn new(mark: Mark, text: impl Into<String>) -> Line {
        Line {
            mark,
            text: text.into(),
        }
    }
}

/// The host's side of an action: nft and sshd for real, a fake in tests.
pub trait Host {
    fn blocked(&self) -> Result<Vec<Blocked>>;
    fn block(&self, ip: IpAddr, hours: u32, cfg: &Config) -> Result<String>;
    fn unblock(&self, ip: IpAddr) -> Result<String>;
    fn disconnect(&self, source: IpAddr, port: Option<u16>) -> Result<Disconnected>;
}

pub struct RealHost;

impl Host for RealHost {
    fn blocked(&self) -> Result<Vec<Blocked>> {
        blocklist::list()
    }
    fn block(&self, ip: IpAddr, hours: u32, cfg: &Config) -> Result<String> {
        blocklist::block(ip, hours, cfg)
    }
    fn unblock(&self, ip: IpAddr) -> Result<String> {
        blocklist::unblock(ip)
    }
    fn disconnect(&self, source: IpAddr, port: Option<u16>) -> Result<Disconnected> {
        sessions::disconnect(source, port)
    }
}

/// One thing done, for "already" answers later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub at: DateTime<Utc>,
    /// "@op (id 42)", or "the CLI".
    pub by: String,
    /// The alert it answered, empty from the CLI.
    pub alert_ref: String,
    /// "block", "unblock", "disconnect".
    pub what: String,
    /// The blocked key (address or /64), or the source.
    pub target: String,
    #[serde(default)]
    pub until: Option<DateTime<Utc>>,
}

/// Most entries kept, and for how long.
const LEDGER_MAX: usize = 500;
const LEDGER_DAYS: i64 = 30;

/// Who did what, kept in the state directory so the CLI and the daemon see
/// the same history.
pub struct Ledger {
    path: Option<PathBuf>,
    mem: Mutex<Vec<Entry>>,
}

impl Ledger {
    pub fn at(path: PathBuf) -> Ledger {
        Ledger {
            path: Some(path),
            mem: Mutex::new(Vec::new()),
        }
    }

    #[cfg(test)]
    pub fn in_memory() -> Ledger {
        Ledger {
            path: None,
            mem: Mutex::new(Vec::new()),
        }
    }

    fn load(&self) -> Vec<Entry> {
        match &self.path {
            Some(p) => std::fs::read_to_string(p)
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default(),
            None => self.mem.lock().map(|m| m.clone()).unwrap_or_default(),
        }
    }

    pub fn record(&self, e: Entry) {
        // Held for the file too, so two writers in this process don't lose
        // each other's entry (load() of a file doesn't take it).
        let Ok(mut mem) = self.mem.lock() else {
            return;
        };
        let mut all = match &self.path {
            Some(_) => self.load(),
            None => std::mem::take(&mut *mem),
        };
        let cutoff = e.at - chrono::Duration::days(LEDGER_DAYS);
        all.retain(|x| x.at > cutoff);
        all.push(e);
        let skip = all.len().saturating_sub(LEDGER_MAX);
        all.drain(..skip);
        match &self.path {
            Some(p) => {
                if let Ok(text) = serde_json::to_string(&all) {
                    let _ = crate::config::write_secure(p, &text);
                }
            }
            None => *mem = all,
        }
    }

    /// The latest `what` on `target`.
    pub fn last(&self, what: &str, target: &str) -> Option<Entry> {
        self.load()
            .into_iter()
            .rev()
            .find(|e| e.what == what && e.target == target)
    }
}

/// The ledger the daemon and the CLI share.
pub fn ledger() -> &'static Ledger {
    static L: OnceLock<Ledger> = OnceLock::new();
    L.get_or_init(|| Ledger::at(crate::paths::state_dir().join("actions.json")))
}

/// Everything a decision needs.
pub struct Ctx<'a> {
    pub host: &'a dyn Host,
    pub ledger: &'a Ledger,
    pub cfg: &'a Config,
    pub by: &'a str,
    pub alert_ref: &'a str,
    pub now: DateTime<Utc>,
}

impl Ctx<'_> {
    fn note(&self, what: &str, target: &str, until: Option<DateTime<Utc>>) {
        self.ledger.record(Entry {
            at: self.now,
            by: self.by.to_string(),
            alert_ref: self.alert_ref.to_string(),
            what: what.to_string(),
            target: target.to_string(),
            until,
        });
    }
}

/// "14:02 UTC", with the date when it isn't today.
pub fn at(now: DateTime<Utc>, t: DateTime<Utc>) -> String {
    if t.date_naive() == now.date_naive() {
        t.format("%H:%M UTC").to_string()
    } else {
        t.format("%H:%M UTC on %-d %b").to_string()
    }
}

/// "until 14:02 UTC tomorrow".
pub fn until(now: DateTime<Utc>, t: DateTime<Utc>) -> String {
    let days = (t.date_naive() - now.date_naive()).num_days();
    match days {
        0 => format!("until {} today", t.format("%H:%M UTC")),
        1 => format!("until {} tomorrow", t.format("%H:%M UTC")),
        _ => format!("until {}", t.format("%H:%M UTC on %-d %b")),
    }
}

/// "@op (id 42)" -> "@op", for short labels.
pub fn short(by: &str) -> &str {
    by.split(" (id ").next().unwrap_or(by)
}

/// A failure as a sentence and a next step. Known causes get their own
/// wording; anything else gets its first line and where the details are.
/// `verb` is what was tried: "block", "unblock", "disconnect".
pub fn explain(e: &anyhow::Error, verb: &str) -> String {
    const DETAILS: &str = "Details: sudo journalctl -u hermian -n 50";
    if let Some(n) = e.downcast_ref::<NftError>() {
        return match n {
            NftError::Missing => format!(
                "Couldn't {}: nftables isn't installed. Run: sudo apt install nftables",
                verb
            ),
            NftError::Timeout(t) => format!(
                "Couldn't {}: nft didn't answer within {}s. Check: sudo hermian blocked",
                verb,
                t.as_secs()
            ),
            NftError::Failed(m) => format!("Couldn't {}: nft said \"{}\". {}", verb, m, DETAILS),
        };
    }
    let first = e.to_string();
    let first = first.lines().next().unwrap_or("").trim();
    if first.is_empty() {
        format!("Couldn't {}. {}", verb, DETAILS)
    } else {
        format!("Couldn't {}: {}. {}", verb, first, DETAILS)
    }
}

fn is_blocked(list: &[Blocked], key: &str) -> Option<String> {
    list.iter()
        .find(|b| b.key == key)
        .map(|b| b.expires.clone())
}

/// Block one address. Already blocked: say since when and by whom, and leave
/// the expiry alone (a second press is a duplicate, not a decision).
pub fn block(ctx: &Ctx, ip: IpAddr) -> Line {
    if let Some(why) = blocklist::refusal(ip, ctx.cfg) {
        return Line::new(Mark::Refused, format!("Not blocked: {}", why));
    }
    let (_, key) = blocklist::block_key(ip);
    let list = match ctx.host.blocked() {
        Ok(l) => l,
        Err(e) => return Line::new(Mark::Failed, explain(&e, "block")),
    };
    if let Some(expires) = is_blocked(&list, &key) {
        let prev = ctx
            .ledger
            .last("block", &key)
            .filter(|e| e.until.is_some_and(|u| u > ctx.now));
        return Line::new(
            Mark::Already,
            match prev {
                Some(p) => format!(
                    "{} already blocked by {} at {}, {}",
                    key,
                    short(&p.by),
                    at(ctx.now, p.at),
                    until(ctx.now, p.until.unwrap_or(ctx.now))
                ),
                None if !expires.is_empty() => {
                    format!("{} already blocked, {} left", key, expires)
                }
                None => format!("{} already blocked", key),
            },
        );
    }
    let hours = ctx.cfg.response.block_duration_hours;
    match ctx.host.block(ip, hours, ctx.cfg) {
        Ok(key) => {
            let end = ctx.now + chrono::Duration::hours(i64::from(hours));
            ctx.note("block", &key, Some(end));
            Line::new(
                Mark::Done,
                format!("Blocked {} {}", key, until(ctx.now, end)),
            )
        }
        Err(e) => Line::new(Mark::Failed, explain(&e, "block")),
    }
}

/// Lift a block. Not blocked: say why not (lifted, by whom, or expired).
pub fn unblock(ctx: &Ctx, ip: IpAddr) -> Line {
    let (_, key) = blocklist::block_key(ip);
    let list = match ctx.host.blocked() {
        Ok(l) => l,
        Err(e) => return Line::new(Mark::Failed, explain(&e, "unblock")),
    };
    if is_blocked(&list, &key).is_none() {
        let lifted = ctx.ledger.last("unblock", &key);
        let blocked = ctx.ledger.last("block", &key);
        let why = match (lifted, blocked) {
            (Some(u), b) if b.as_ref().is_none_or(|b| u.at >= b.at) => {
                format!(", lifted by {} at {}", short(&u.by), at(ctx.now, u.at))
            }
            (_, Some(b)) if b.until.is_some_and(|t| t <= ctx.now) => format!(
                ", the block expired at {}",
                at(ctx.now, b.until.unwrap_or(ctx.now))
            ),
            _ => String::new(),
        };
        return Line::new(Mark::Already, format!("{} isn't blocked{}", key, why));
    }
    match ctx.host.unblock(ip) {
        Ok(key) => {
            ctx.note("unblock", &key, None);
            Line::new(Mark::Done, format!("Unblocked {}", key))
        }
        Err(e) => Line::new(Mark::Failed, explain(&e, "unblock")),
    }
}

/// End the SSH session(s) from `source`.
pub fn disconnect(ctx: &Ctx, source: IpAddr, port: Option<u16>, user: &str) -> Line {
    match ctx.host.disconnect(source, port) {
        Ok(d) => {
            ctx.note("disconnect", &source.to_string(), None);
            let sessions = if d.connections > 1 {
                format!(" ({} sessions)", d.connections)
            } else {
                String::new()
            };
            let text = if user.is_empty() {
                format!("Disconnected {}{}", source, sessions)
            } else {
                format!("Disconnected {} from {}{}", user, source, sessions)
            };
            Line::new(Mark::Done, text)
        }
        Err(e) => match e.downcast_ref::<DisconnectError>() {
            Some(DisconnectError::NotConnected) => Line::new(
                Mark::Already,
                format!("Nobody from {} is connected", source),
            ),
            Some(DisconnectError::NoSshd) => Line::new(
                Mark::Failed,
                format!(
                    "Couldn't disconnect {}: no sshd process held the connection, it may have \
                     just closed. Check: who",
                    source
                ),
            ),
            None => Line::new(Mark::Failed, explain(&e, "disconnect")),
        },
    }
}

/// What still lets them in after a disconnect, so nobody mistakes it for a
/// lockout.
pub fn after_disconnect(blocked: bool) -> Line {
    Line::new(
        Mark::Note,
        if blocked {
            "Their key or password still works from other addresses."
        } else {
            "Nothing stops them logging back in."
        },
    )
}

/// The result message: one line per target, then where, who and when.
pub fn render(host: &str, by: &str, lines: &[Line], now: DateTime<Utc>) -> String {
    let mut out = String::new();
    for l in lines {
        if l.mark != Mark::Note {
            out.push_str(l.mark.sign());
            out.push(' ');
        }
        out.push_str(&l.text);
        out.push('\n');
    }
    out.push_str(&format!(
        "{} · {} · {}",
        host,
        short(by),
        now.format("%H:%M UTC")
    ));
    out
}

/// What the action did, in the past tense, for the label on the alert.
fn done_as(a: &ResponseAction) -> String {
    use ResponseAction as A;
    match a {
        A::Block { sources } if sources.len() == 1 => format!("Blocked {}", sources[0]),
        A::Block { sources } => format!("Blocked {}", sources.len()),
        A::Unblock { sources } if sources.len() == 1 => format!("Unblocked {}", sources[0]),
        A::Unblock { .. } => "Unblocked".to_string(),
        A::Disconnect { block: true, .. } => "Disconnected and blocked".to_string(),
        A::Disconnect { .. } => "Disconnected".to_string(),
        A::Ignore { hours, sources } if *hours > 0 && !sources.is_empty() => {
            format!("Ignored for {}h", hours)
        }
        A::Ignore { .. } => "Ignored".to_string(),
        A::SnoozeRootPasswordWarning { days } => format!("Snoozed {} days", days),
    }
}

/// The label a used button becomes: "✓ Blocked 203.0.113.24 · @op 14:02 UTC".
pub fn summary(a: &ResponseAction, lines: &[Line], by: &str, now: DateTime<Utc>) -> String {
    let marks: Vec<Mark> = lines
        .iter()
        .map(|l| l.mark)
        .filter(|m| *m != Mark::Note)
        .collect();
    let all = |m: Mark| !marks.is_empty() && marks.iter().all(|x| *x == m);
    let head = if all(Mark::Done) {
        format!("✓ {}", done_as(a))
    } else if all(Mark::Already) {
        "· Already the case".to_string()
    } else if all(Mark::Refused) {
        "⊘ Refused".to_string()
    } else if all(Mark::Failed) {
        "✗ Failed".to_string()
    } else if marks.contains(&Mark::Done) {
        "◐ Partly done".to_string()
    } else {
        "✗ Not done".to_string()
    };
    format!("{} · {} {}", head, short(by), now.format("%H:%M UTC"))
}

/// Whether the result is worth its own message under the alert. Choices
/// that change nothing on the host (Ignore, Snooze) only update the label,
/// unless something was refused or failed.
pub fn needs_reply(a: &ResponseAction, lines: &[Line]) -> bool {
    use ResponseAction as A;
    matches!(
        a,
        A::Block { .. } | A::Unblock { .. } | A::Disconnect { .. }
    ) || lines
        .iter()
        .any(|l| matches!(l.mark, Mark::Refused | Mark::Failed))
}

/// `hermian block <ip>...`: the CLI twin of the Block button.
pub fn cmd_block(ips: &[String]) -> Result<()> {
    crate::config::require_root()?;
    let cfg = crate::config::load_config()?;
    let ips = parse_ips(ips)?;
    let ctx = cli_ctx(&cfg);
    finish_cli(ips.iter().map(|ip| block(&ctx, *ip)).collect())
}

/// `hermian unblock <ip>`.
pub fn cmd_unblock(ip: &str) -> Result<()> {
    crate::config::require_root()?;
    let cfg = crate::config::load_config()?;
    let ips = parse_ips(&[ip.to_string()])?;
    let ctx = cli_ctx(&cfg);
    finish_cli(vec![unblock(&ctx, ips[0])])
}

/// `hermian disconnect <ip>`: the CLI twin of Disconnect.
pub fn cmd_disconnect(ip: &str) -> Result<()> {
    crate::config::require_root()?;
    let cfg = crate::config::load_config()?;
    let ips = parse_ips(&[ip.to_string()])?;
    let ctx = cli_ctx(&cfg);
    let line = disconnect(&ctx, ips[0], None, "");
    let done = line.mark == Mark::Done;
    let mut lines = vec![line];
    if done {
        lines.push(after_disconnect(false));
    }
    finish_cli(lines)
}

fn cli_ctx(cfg: &Config) -> Ctx<'_> {
    Ctx {
        host: &RealHost,
        ledger: ledger(),
        cfg,
        by: "the CLI",
        alert_ref: "",
        now: Utc::now(),
    }
}

fn parse_ips(raw: &[String]) -> Result<Vec<IpAddr>> {
    raw.iter()
        .map(|s| {
            s.trim()
                .split('/')
                .next()
                .unwrap_or("")
                .parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("'{}' is not an IP address", s))
        })
        .collect()
}

fn finish_cli(lines: Vec<Line>) -> Result<()> {
    let st = crate::ui::Style::detect();
    for l in &lines {
        let text = if l.mark == Mark::Note {
            format!("  {}", l.text)
        } else {
            format!("{} {}", l.mark.sign(), l.text)
        };
        println!(
            "{}",
            match l.mark {
                Mark::Done => st.ok(&text),
                Mark::Failed | Mark::Refused => st.bad(&text),
                _ => st.dim(&text),
            }
        );
    }
    if lines
        .iter()
        .any(|l| matches!(l.mark, Mark::Failed | Mark::Refused))
    {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A firewall and sshd in memory.
    #[derive(Default)]
    struct Fake {
        blocked: RefCell<Vec<Blocked>>,
        block_calls: RefCell<u32>,
        nft: Option<NftError>,
        disconnect: Option<DisconnectError>,
    }

    impl Host for Fake {
        fn blocked(&self) -> Result<Vec<Blocked>> {
            match &self.nft {
                Some(e) => Err(e.clone().into()),
                None => Ok(self.blocked.borrow().clone()),
            }
        }
        fn block(&self, ip: IpAddr, hours: u32, _: &Config) -> Result<String> {
            *self.block_calls.borrow_mut() += 1;
            let (_, key) = blocklist::block_key(ip);
            self.blocked.borrow_mut().push(Blocked {
                key: key.clone(),
                expires: format!("{}h", hours),
            });
            Ok(key)
        }
        fn unblock(&self, ip: IpAddr) -> Result<String> {
            let (_, key) = blocklist::block_key(ip);
            self.blocked.borrow_mut().retain(|b| b.key != key);
            Ok(key)
        }
        fn disconnect(&self, _: IpAddr, _: Option<u16>) -> Result<Disconnected> {
            match self.disconnect {
                Some(e) => Err(e.into()),
                None => Ok(Disconnected {
                    connections: 1,
                    processes: vec![4242],
                }),
            }
        }
    }

    fn cfg() -> Config {
        let mut c = Config::default();
        c.response.management_cidrs = vec!["10.0.0.0/8".into()];
        c.response.block_duration_hours = 24;
        c
    }

    fn t(h: u32, m: u32) -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(2026, 10, 18, h, m, 0).unwrap()
    }

    fn ctx<'a>(
        host: &'a Fake,
        ledger: &'a Ledger,
        cfg: &'a Config,
        by: &'a str,
        now: DateTime<Utc>,
    ) -> Ctx<'a> {
        Ctx {
            host,
            ledger,
            cfg,
            by,
            alert_ref: "HER-2026-1018-009",
            now,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_second_block_says_already_and_keeps_the_expiry() {
        let (host, ledger, cfg) = (Fake::default(), Ledger::in_memory(), cfg());
        let first = block(
            &ctx(&host, &ledger, &cfg, "@op (id 42)", t(14, 2)),
            ip("203.0.113.24"),
        );
        assert_eq!(first.mark, Mark::Done);
        assert_eq!(first.text, "Blocked 203.0.113.24 until 14:02 UTC tomorrow");
        let second = block(
            &ctx(&host, &ledger, &cfg, "@bob (id 7)", t(14, 30)),
            ip("203.0.113.24"),
        );
        assert_eq!(second.mark, Mark::Already);
        assert_eq!(
            second.text,
            "203.0.113.24 already blocked by @op at 14:02 UTC, until 14:02 UTC tomorrow"
        );
        assert_eq!(*host.block_calls.borrow(), 1, "the timer wasn't restarted");
    }

    #[test]
    fn a_block_from_elsewhere_is_still_already() {
        let (host, ledger, cfg) = (Fake::default(), Ledger::in_memory(), cfg());
        host.blocked.borrow_mut().push(Blocked {
            key: "203.0.113.24".into(),
            expires: "3h12m".into(),
        });
        let l = block(
            &ctx(&host, &ledger, &cfg, "@op (id 42)", t(9, 0)),
            ip("203.0.113.24"),
        );
        assert_eq!(l.mark, Mark::Already);
        assert_eq!(l.text, "203.0.113.24 already blocked, 3h12m left");
    }

    #[test]
    fn safety_rules_refuse_and_name_the_setting() {
        let (host, ledger, cfg) = (Fake::default(), Ledger::in_memory(), cfg());
        let l = block(
            &ctx(&host, &ledger, &cfg, "@op (id 42)", t(9, 0)),
            ip("10.0.0.5"),
        );
        assert_eq!(l.mark, Mark::Refused);
        assert_eq!(
            l.text,
            "Not blocked: 10.0.0.5 is inside your management network 10.0.0.0/8 (response.management_cidrs)"
        );
        assert_eq!(*host.block_calls.borrow(), 0);
    }

    #[test]
    fn nft_trouble_says_what_to_do() {
        let ledger = Ledger::in_memory();
        let cfg = cfg();
        let missing = Fake {
            nft: Some(NftError::Missing),
            ..Fake::default()
        };
        let l = block(
            &ctx(&missing, &ledger, &cfg, "@op (id 42)", t(9, 0)),
            ip("203.0.113.24"),
        );
        assert_eq!(l.mark, Mark::Failed);
        assert_eq!(
            l.text,
            "Couldn't block: nftables isn't installed. Run: sudo apt install nftables"
        );
        let slow = Fake {
            nft: Some(NftError::Timeout(std::time::Duration::from_secs(10))),
            ..Fake::default()
        };
        let l = block(
            &ctx(&slow, &ledger, &cfg, "@op (id 42)", t(9, 0)),
            ip("203.0.113.24"),
        );
        assert!(
            l.text
                .contains("nft didn't answer within 10s. Check: sudo hermian blocked"),
            "{}",
            l.text
        );
    }

    #[test]
    fn undo_after_a_cli_unblock_says_who_lifted_it() {
        let (host, ledger, cfg) = (Fake::default(), Ledger::in_memory(), cfg());
        block(
            &ctx(&host, &ledger, &cfg, "@op (id 42)", t(14, 2)),
            ip("203.0.113.24"),
        );
        let cli = unblock(
            &ctx(&host, &ledger, &cfg, "the CLI", t(15, 10)),
            ip("203.0.113.24"),
        );
        assert_eq!(cli.mark, Mark::Done);
        let undo = unblock(
            &ctx(&host, &ledger, &cfg, "@op (id 42)", t(15, 20)),
            ip("203.0.113.24"),
        );
        assert_eq!(undo.mark, Mark::Already);
        assert_eq!(
            undo.text,
            "203.0.113.24 isn't blocked, lifted by the CLI at 15:10 UTC"
        );
    }

    #[test]
    fn an_expired_block_says_so() {
        let (host, ledger, cfg) = (Fake::default(), Ledger::in_memory(), cfg());
        block(
            &ctx(&host, &ledger, &cfg, "@op (id 42)", t(1, 0)),
            ip("203.0.113.24"),
        );
        host.blocked.borrow_mut().clear(); // the kernel's timeout ran out
        let tomorrow = t(1, 0) + chrono::Duration::hours(30);
        let l = unblock(
            &ctx(&host, &ledger, &cfg, "@op (id 42)", tomorrow),
            ip("203.0.113.24"),
        );
        assert_eq!(l.mark, Mark::Already);
        assert!(
            l.text.ends_with(", the block expired at 01:00 UTC"),
            "{}",
            l.text
        );
    }

    #[test]
    fn disconnect_outcomes() {
        let (ledger, cfg) = (Ledger::in_memory(), cfg());
        let gone = Fake {
            disconnect: Some(DisconnectError::NotConnected),
            ..Fake::default()
        };
        let l = disconnect(
            &ctx(&gone, &ledger, &cfg, "@op (id 42)", t(9, 0)),
            ip("203.0.113.24"),
            None,
            "root",
        );
        assert_eq!(l.mark, Mark::Already);
        assert_eq!(l.text, "Nobody from 203.0.113.24 is connected");
        let odd = Fake {
            disconnect: Some(DisconnectError::NoSshd),
            ..Fake::default()
        };
        let l = disconnect(
            &ctx(&odd, &ledger, &cfg, "@op (id 42)", t(9, 0)),
            ip("203.0.113.24"),
            None,
            "root",
        );
        assert_eq!(l.mark, Mark::Failed);
        assert!(
            l.text.contains("it may have just closed. Check: who"),
            "{}",
            l.text
        );
        let ok = Fake::default();
        let l = disconnect(
            &ctx(&ok, &ledger, &cfg, "@op (id 42)", t(9, 0)),
            ip("203.0.113.24"),
            Some(4),
            "root",
        );
        assert_eq!(l.text, "Disconnected root from 203.0.113.24");
        assert!(after_disconnect(true)
            .text
            .contains("still works from other addresses"));
    }

    #[test]
    fn no_reply_leaks_raw_errors() {
        let errors: Vec<anyhow::Error> = vec![
            NftError::Missing.into(),
            NftError::Timeout(std::time::Duration::from_secs(10)).into(),
            NftError::Failed("Error: Could not process rule".into()).into(),
            DisconnectError::NoSshd.into(),
            anyhow::anyhow!(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            anyhow::anyhow!(""),
        ];
        for e in &errors {
            let s = explain(e, "block");
            assert!(!s.starts_with("Error"), "{}", s);
            assert!(
                !s.contains("Os {") && !s.contains("anyhow") && !s.contains("Kind("),
                "{}",
                s
            );
            assert!(s.contains("sudo "), "no next step: {}", s);
            assert!(!s.contains(": ."), "empty cause: {}", s);
        }
    }

    #[test]
    fn the_result_is_one_line_per_target_then_where_who_and_when() {
        let lines = vec![
            Line::new(Mark::Done, "Blocked 203.0.113.24 until 14:02 UTC tomorrow"),
            Line::new(Mark::Failed, "Couldn't disconnect 203.0.113.24: ..."),
            after_disconnect(true),
        ];
        let text = render("web-01", "@op (id 42)", &lines, t(14, 2));
        assert_eq!(
            text,
            "✓ Blocked 203.0.113.24 until 14:02 UTC tomorrow\n\
             ✗ Couldn't disconnect 203.0.113.24: ...\n\
             Their key or password still works from other addresses.\n\
             web-01 · @op · 14:02 UTC"
        );
        let d = ResponseAction::Disconnect {
            source: ip("203.0.113.24"),
            port: None,
            user: "root".into(),
            block: true,
        };
        assert_eq!(
            summary(&d, &lines, "@op (id 42)", t(14, 2)),
            "◐ Partly done · @op 14:02 UTC"
        );
        assert_eq!(
            summary(&d, &lines[..1], "@op (id 42)", t(14, 2)),
            "✓ Disconnected and blocked · @op 14:02 UTC"
        );
    }

    #[test]
    fn ignore_only_updates_the_label_unless_something_went_wrong() {
        let ignore = ResponseAction::Ignore {
            sources: vec![],
            hours: 0,
        };
        let block = ResponseAction::Block {
            sources: vec![ip("203.0.113.24")],
        };
        let done = vec![Line::new(Mark::Done, "Ignored")];
        assert!(!needs_reply(&ignore, &done));
        assert!(needs_reply(&block, &done));
        assert!(needs_reply(
            &ignore,
            &[Line::new(Mark::Failed, "Couldn't ignore")]
        ));
        assert_eq!(
            summary(&ignore, &done, "@op (id 42)", t(9, 22)),
            "✓ Ignored · @op 09:22 UTC"
        );
    }

    #[test]
    fn the_ledger_survives_on_disk_and_stays_bounded() {
        let dir = std::env::temp_dir().join(format!("hermian-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("actions.json");
        let l = Ledger::at(path.clone());
        for i in 0..(LEDGER_MAX + 20) {
            l.record(Entry {
                at: t(9, 0),
                by: "@op".into(),
                alert_ref: String::new(),
                what: "block".into(),
                target: format!("198.51.100.{}", i % 250),
                until: None,
            });
        }
        let again = Ledger::at(path);
        assert_eq!(again.load().len(), LEDGER_MAX);
        assert!(again.last("block", "198.51.100.19").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
