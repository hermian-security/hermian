mod alerts;
mod audit;
mod auditnetlink;
mod authlog;
mod blocklist;
mod btf;
mod channels;
mod cli;
mod collect;
mod config;
mod configdiff;
mod confmerge;
mod daemon;
mod ebpf;
mod enable;
mod fallback;
mod health;
mod heartbeat;
mod isolate;
mod notify;
mod pamsock;
mod paths;
mod procsrc;
mod report;
mod retention;
mod selfprotect;
mod sessions;
mod sshkeys;
mod status;
mod tgbot;
mod ui;
mod uninstall;
mod watchdog;
mod watchers;

use clap::FromArgMatches;

fn main() {
    let cli =
        cli::Cli::from_arg_matches(&cli::command().get_matches()).unwrap_or_else(|e| e.exit());
    let result = match cli.cmd {
        cli::Cmd::Run => daemon::run(),
        cli::Cmd::Enable(args) => enable::run(&args),
        cli::Cmd::Status(args) => status::cmd_status(args.json),
        cli::Cmd::Alerts(args) => alerts::cmd_alerts(&args),
        cli::Cmd::Report(args) => report::cmd_report(&args),
        cli::Cmd::Show(args) => alerts::cmd_show(&args),
        cli::Cmd::Test(args) => cli::cmd_test(&args),
        cli::Cmd::Audit(args) => audit::cmd_audit(&args),
        cli::Cmd::NotifyTest(args) => cli::cmd_notify_test(&args),
        cli::Cmd::Collect(args) => collect::run(&args),
        cli::Cmd::Isolate(args) => isolate::cmd_isolate(&args),
        cli::Cmd::Unisolate => isolate::cmd_unisolate(),
        cli::Cmd::Blocked => blocklist::cmd_blocked(),
        cli::Cmd::Unblock(args) => blocklist::cmd_unblock(&args.ip),
        cli::Cmd::Uninstall(args) => uninstall::run(&args),
        cli::Cmd::Watchdog => watchdog::run(),
    };
    if let Err(e) = result {
        let st = ui::Style::detect();
        eprintln!("{} {:#}", st.bad("hermian:"), e);
        std::process::exit(1);
    }
}
