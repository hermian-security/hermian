use anyhow::Result;
use clap::{Parser, Subcommand};
use hermian_core::{render, Severity};

use crate::ui::Style;

#[derive(Parser)]
#[command(
    name = "hermian",
    version,
    about = "An intrusion alarm for Linux servers. It watches the host and only\nspeaks up when something looks like a real compromise."
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// The top-level help, grouped by what people reach for. Every visible
/// subcommand must appear here (a test checks it).
const COMMAND_GROUPS: &[(&str, &[(&str, &str)])] = &[
    (
        "Everyday",
        &[
            (
                "status",
                "Is this host protected? Coverage, delivery, overhead",
            ),
            ("alerts", "Recent alerts, LOW and up (--all adds INFO)"),
            (
                "show <ref>",
                "One alert in full: chain, evidence, risk, next steps",
            ),
            (
                "report",
                "A week's summary to share, with nothing private in it",
            ),
            ("collect <ref>", "Gather local context for an alert"),
        ],
    ),
    (
        "Setup",
        &[
            ("enable", "Install, enable and start; re-run after upgrades"),
            ("notify-test", "Check alert channels and send a test alert"),
            ("test", "Self-test against synthetic attacks"),
        ],
    ),
    (
        "Response",
        &[
            ("blocked", "Addresses blocked from Telegram buttons"),
            ("unblock <ip>", "Lift a block before it expires"),
            ("isolate", "Cut the network, keep your management access"),
            ("unisolate", "Lift isolation"),
        ],
    ),
    ("Remove", &[("uninstall", "Remove Hermian from this host")]),
];

/// `hermian`'s command, dressed in the identity: the banner on top, the
/// commands grouped, brand colours, examples and links at the end. The
/// colours are only used on a terminal (and not with NO_COLOR).
pub fn command() -> clap::Command {
    use clap::builder::styling::{Ansi256Color, AnsiColor, Styles};
    use clap::CommandFactory;
    let st = Style::detect();
    let accent = Ansi256Color(141).on_default();
    let styles = Styles::styled()
        .header(accent.bold())
        .usage(accent.bold())
        .literal(AnsiColor::BrightWhite.on_default().bold())
        .placeholder(AnsiColor::BrightBlack.on_default())
        .valid(accent)
        .invalid(Ansi256Color(204).on_default().bold())
        .error(Ansi256Color(204).on_default().bold());

    let mut groups = String::new();
    for (name, cmds) in COMMAND_GROUPS {
        groups.push_str(&format!("{}\n", st.accent(&st.bold(name))));
        for (cmd, what) in *cmds {
            groups.push_str(&format!(
                "  {}{}{}\n",
                st.bold(cmd),
                " ".repeat(16usize.saturating_sub(cmd.chars().count())),
                what
            ));
        }
        groups.push('\n');
    }
    let after = format!(
        "{}\n  sudo hermian status\n  sudo hermian alerts -s high\n  sudo hermian show 7\n\n\
         {}\n  NO_COLOR=1, or HERMIAN_COLOR=always|never\n\n\
         {}  https://hermian.me/docs\n{}  https://github.com/hermian-security/hermian\n\
         {}  contact@hermian.me (security reports: SECURITY.md)",
        st.accent(&st.bold("Examples")),
        st.accent(&st.bold("Colour")),
        st.dim("Docs    "),
        st.dim("Code    "),
        st.dim("Contact ")
    );
    Cli::command()
        .styles(styles)
        .before_help(format!("\n{}", st.brand(hermian_core::VERSION)))
        .help_template(format!(
            "{{before-help}}{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{}{}\n\
             {{options}}\n\nRun 'hermian <command> --help' for its options.{{after-help}}",
            groups,
            st.accent(&st.bold("Options"))
        ))
        .after_help(after)
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Install, enable and start the daemon (idempotent; re-run after upgrades)
    Enable(EnableArgs),
    /// Show protection status
    Status(StatusArgs),
    /// List recent alerts
    Alerts(AlertsArgs),
    /// Show one alert in full
    Show(ShowArgs),
    /// Run the detection self-test against synthetic attack scenarios
    Test(TestArgs),
    /// Verify notification channels and send a test alert through them
    NotifyTest(NotifyTestArgs),
    /// Collect a forensic context bundle for an alert
    Collect(CollectArgs),
    /// Summary to share with the maintainers: versions and counts, nothing private
    Report(ReportArgs),
    /// Isolate the host from the network (management CIDRs stay reachable)
    Isolate(IsolateArgs),
    /// Remove network isolation
    Unisolate,
    /// List addresses blocked with the Telegram "Block" buttons
    Blocked,
    /// Lift a block before it expires
    Unblock(UnblockArgs),
    /// Completely remove Hermian from this host
    Uninstall(UninstallArgs),
    /// Run the daemon (used by the systemd unit)
    #[command(hide = true)]
    Run,
    /// Dead-man switch (used by the hermian-watchdog systemd timer)
    #[command(hide = true)]
    Watchdog,
}

#[derive(clap::Args)]
pub struct ReportArgs {
    /// How many days of alerts to count
    #[arg(long, default_value_t = 7)]
    pub days: u32,
    /// Emit JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct EnableArgs {
    /// Skip the baseline learning period (use on freshly provisioned hosts)
    #[arg(long)]
    pub no_baseline: bool,
    /// Also hook the optional PAM module into sshd
    #[arg(long)]
    pub with_pam: bool,
    /// Do not print status after enabling
    #[arg(long, short)]
    pub quiet: bool,
}

#[derive(clap::Args)]
pub struct StatusArgs {
    /// Machine-readable output
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct AlertsArgs {
    /// Show this alert in full instead (`hermian alerts 182`, or `alerts show 182`)
    #[arg(value_name = "REF", num_args = 0..=2)]
    pub reference: Vec<String>,
    /// Maximum number of alerts to list
    #[arg(long, short = 'n', default_value_t = 20)]
    pub limit: usize,
    /// Only alerts at or above this severity (INFO, LOW, HIGH, CRITICAL); default LOW
    #[arg(long, short = 's')]
    pub severity: Option<String>,
    /// Include INFO alerts (context, never notified)
    #[arg(long, short = 'a')]
    pub all: bool,
    /// Only alerts from this detection (D1..D5, SELF)
    #[arg(long, short = 'd')]
    pub detection: Option<String>,
    /// Emit newline-delimited JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct ShowArgs {
    /// Alert reference, e.g. HER-2025-0914-001 (or just 001 for today)
    pub ref_id: String,
    /// Emit JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct TestArgs {
    /// Print every generated sample alert, not just the first
    #[arg(long, short)]
    pub verbose: bool,
    /// Emit the sample alerts as newline-delimited JSON (for integrations)
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct NotifyTestArgs {
    /// Only test this channel (telegram, email, webhook); default: all configured
    #[arg(long, short)]
    pub channel: Option<String>,
    /// Probe connectivity/credentials only; do not send a message
    #[arg(long)]
    pub probe_only: bool,
    /// Severity of the test alert (affects Telegram sound and email colour)
    #[arg(long, default_value = "HIGH")]
    pub severity: String,
}

#[derive(clap::Args)]
pub struct CollectArgs {
    /// Alert reference, e.g. HER-2025-0914-001
    pub ref_id: String,
}

#[derive(clap::Args)]
pub struct IsolateArgs {
    /// Lift the isolation automatically after this many minutes (a systemd
    /// timer, so it works even if you can't get back in)
    #[arg(long = "for", value_name = "MINUTES", value_parser = clap::value_parser!(u32).range(1..=10080))]
    pub for_mins: Option<u32>,
}

#[derive(clap::Args)]
pub struct UnblockArgs {
    /// The blocked address (for IPv6, any address in the blocked /64)
    pub ip: String,
}

#[derive(clap::Args)]
pub struct UninstallArgs {
    /// Do not ask for confirmation
    #[arg(long)]
    pub yes: bool,
}

pub fn cmd_test(args: &TestArgs) -> Result<()> {
    let st = Style::detect();
    let results = hermian_core::selftest::run_selftests();
    let passed = results.iter().filter(|r| r.pass).count();

    if args.json {
        for r in &results {
            if let Some(a) = &r.sample_alert {
                println!("{}", serde_json::to_string(a)?);
            }
        }
        return if passed == results.len() {
            Ok(())
        } else {
            anyhow::bail!(
                "{} of {} scenarios failed",
                results.len() - passed,
                results.len()
            )
        };
    }

    println!(
        "{}",
        st.masthead("self-test", &format!("{} scenarios", results.len()))
    );
    for r in &results {
        let mark = if r.pass {
            st.ok("PASS")
        } else {
            st.bad("FAIL")
        };
        let sev = st.sev(r.expected, &format!("{:<8}", r.expected.as_str()));
        println!(
            "  {}  {}  {}  {}",
            mark,
            st.dim(r.detection.short()),
            sev,
            r.name
        );
        if !r.pass {
            println!("               {}", st.warn(&r.detail));
        }
    }
    println!("{}", st.rule());

    if passed == results.len() {
        println!(
            "  {}",
            st.ok(&format!(
                "All {} scenarios detected at the expected severity.",
                passed
            ))
        );
        let samples: Vec<_> = results
            .iter()
            .filter_map(|r| r.sample_alert.as_ref())
            .collect();
        let to_show: Vec<_> = if args.verbose {
            samples
        } else {
            samples.into_iter().take(1).collect()
        };
        if !to_show.is_empty() {
            println!();
            println!(
                "  {}",
                st.dim(if args.verbose {
                    "Sample alerts, exactly as they are written to journald and the alert log:"
                } else {
                    "Sample alert, exactly as it is written to journald and the alert log (use --verbose for all):"
                })
            );
            for a in to_show {
                println!();
                print!("{}", render(a, st.theme()));
            }
        }
        Ok(())
    } else {
        anyhow::bail!(
            "{} of {} scenarios failed",
            results.len() - passed,
            results.len()
        )
    }
}

pub fn cmd_notify_test(args: &NotifyTestArgs) -> Result<()> {
    use hermian_core::{Alert, DetectionId, Finding};
    let st = Style::detect();
    let cfg = crate::config::load_config()?;
    let n = &cfg.notifications;
    let severity: Severity = args
        .severity
        .parse()
        .map_err(|_| anyhow::anyhow!("unknown severity '{}'", args.severity))?;

    let mut channels: Vec<&str> = crate::notify::NOTIFYING_CHANNELS
        .iter()
        .copied()
        .filter(|c| *c != "stdout" && n.has_channel(c))
        .collect();
    if let Some(only) = &args.channel {
        if !channels.contains(&only.as_str()) {
            anyhow::bail!(
                "channel '{}' is not enabled in notifications.channels (enabled: {})",
                only,
                n.channels.join(", ")
            );
        }
        channels.retain(|c| c == only);
    }
    if channels.is_empty() {
        println!("{}", st.masthead("notification test", ""));
        println!("  {}", st.warn("No notifying channel is enabled."));
        println!("  Add \"telegram\", \"email\" or \"webhook\" to notifications.channels in");
        println!("  /etc/hermian/config.toml and fill in the matching [notifications.*] section.");
        return Ok(());
    }

    println!(
        "{}",
        st.masthead(
            "notification test",
            &format!("{} channel(s)", channels.len())
        )
    );

    let host = crate::procsrc::hostname();
    let finding = Finding::new(
        DetectionId::Self_,
        severity,
        "Notification test",
        "selftest|notify",
    )
    .what(format!(
        "This is a test alert requested by an operator with 'hermian notify-test' on {}. \
         No detection fired.",
        host
    ))
    .fact("Channels", channels.join(", "))
    .why("It confirms this delivery path works end to end so you can trust that silence means safety.")
    .action("Nothing. If you did not run this command, investigate who did.");
    let alert = Alert::from_finding(
        finding,
        format!("HER-TEST-{}", chrono::Utc::now().format("%H%M%S")),
        host,
        chrono::Utc::now(),
    );

    let mut failed = 0;
    for ch in &channels {
        let probe = match *ch {
            "telegram" => crate::channels::telegram::probe(&n.telegram),
            "email" => crate::channels::email::probe(&n.email),
            "webhook" => Ok(format!(
                "{} ({})",
                crate::notify::webhook::display_url(&n.webhook.url),
                n.webhook.format
            )),
            _ => Ok(String::new()),
        };
        match probe {
            Ok(info) => println!("  {}  {:<9} {}", st.ok("OK  "), ch, st.dim(&info)),
            Err(e) => {
                failed += 1;
                println!("  {}  {:<9} {}", st.bad("FAIL"), ch, st.warn(&e));
                continue;
            }
        }
        if args.probe_only {
            continue;
        }
        match crate::notify::notify_one(ch, &alert, n) {
            Ok(()) => println!(
                "  {}  {:<9} {}",
                st.ok("SENT"),
                ch,
                st.dim(&format!("{} test alert delivered", severity))
            ),
            Err(e) => {
                failed += 1;
                println!("  {}  {:<9} {}", st.bad("FAIL"), ch, st.warn(&e));
            }
        }
    }
    println!("{}", st.rule());
    if failed == 0 {
        println!(
            "  {}",
            st.ok(if args.probe_only {
                "All channels reachable."
            } else {
                "All channels delivered. Check your inbox / chat."
            })
        );
        Ok(())
    } else {
        anyhow::bail!("{} channel(s) failed", failed)
    }
}

pub fn severity_filter(s: Option<&str>) -> Result<Option<Severity>> {
    match s {
        None => Ok(None),
        Some(v) => v
            .parse::<Severity>()
            .map(Some)
            .map_err(|_| anyhow::anyhow!("unknown severity '{}' (INFO, LOW, HIGH, CRITICAL)", v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_lists_every_visible_command_once() {
        let listed: Vec<&str> = COMMAND_GROUPS
            .iter()
            .flat_map(|(_, cmds)| cmds.iter())
            .map(|(cmd, _)| cmd.split_whitespace().next().unwrap())
            .collect();
        let mut visible: Vec<String> = command()
            .get_subcommands()
            .filter(|c| !c.is_hide_set() && c.get_name() != "help")
            .map(|c| c.get_name().to_string())
            .collect();
        visible.sort();
        let mut sorted = listed.clone();
        sorted.sort();
        assert_eq!(sorted, visible);
    }

    #[test]
    fn help_renders() {
        let help = command().render_help().to_string();
        assert!(help.contains("hermian"), "{}", help);
        assert!(help.contains("Everyday"), "{}", help);
        assert!(!help.contains("\n\n\n"), "{:?}", help);
    }
}
