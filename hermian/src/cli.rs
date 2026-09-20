use anyhow::Result;
use clap::{Parser, Subcommand};
use hermian_core::{render, Severity};

use crate::ui::Style;

#[derive(Parser)]
#[command(
    name = "hermian",
    version,
    about = "HERMIAN - silent by default, loud when it matters.",
    long_about = "HERMIAN is a lightweight defensive security daemon for Linux. It detects \
                  high-confidence signs of compromise with deterministic, contextual rules and \
                  only interrupts you when something genuinely requires attention.",
    after_help = "Environment:\n  NO_COLOR=1 / HERMIAN_COLOR=always|never   control terminal colour\n\nDocs: https://github.com/hermian-security/hermian"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
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
    /// Collect a forensic context bundle for an alert
    Collect(CollectArgs),
    /// Isolate the host from the network (management CIDRs stay reachable)
    Isolate,
    /// Remove network isolation
    Unisolate,
    /// Completely remove HERMIAN from this host
    Uninstall(UninstallArgs),
    /// Run the daemon (used by the systemd unit)
    #[command(hide = true)]
    Run,
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
    /// Maximum number of alerts to list
    #[arg(long, short = 'n', default_value_t = 20)]
    pub limit: usize,
    /// Only alerts at or above this severity (INFO, LOW, HIGH, CRITICAL)
    #[arg(long, short = 's')]
    pub severity: Option<String>,
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
pub struct CollectArgs {
    /// Alert reference, e.g. HER-2025-0914-001
    pub ref_id: String,
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
        st.banner(
            "HERMIAN detection self-test",
            &format!("{} scenarios", results.len())
        )
    );
    println!("{}", st.rule());
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

pub fn severity_filter(s: Option<&str>) -> Result<Option<Severity>> {
    match s {
        None => Ok(None),
        Some(v) => v
            .parse::<Severity>()
            .map(Some)
            .map_err(|_| anyhow::anyhow!("unknown severity '{}' (INFO, LOW, HIGH, CRITICAL)", v)),
    }
}
