mod alerts;
mod auditnetlink;
mod authlog;
mod btf;
mod cli;
mod collect;
mod config;
mod daemon;
mod ebpf;
mod enable;
mod fallback;
mod isolate;
mod notify;
mod pamsock;
mod paths;
mod procsrc;
mod selfprotect;
mod status;
mod ui;
mod uninstall;
mod watchers;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    let result = match cli.cmd {
        cli::Cmd::Run => daemon::run(),
        cli::Cmd::Enable(args) => enable::run(&args),
        cli::Cmd::Status(args) => status::cmd_status(args.json),
        cli::Cmd::Alerts(args) => alerts::cmd_alerts(&args),
        cli::Cmd::Show(args) => alerts::cmd_show(&args),
        cli::Cmd::Test(args) => cli::cmd_test(&args),
        cli::Cmd::Collect(args) => collect::run(&args),
        cli::Cmd::Isolate => isolate::cmd_isolate(),
        cli::Cmd::Unisolate => isolate::cmd_unisolate(),
        cli::Cmd::Uninstall(args) => uninstall::run(&args),
    };
    if let Err(e) = result {
        let st = ui::Style::detect();
        eprintln!("{} {:#}", st.bad("hermian:"), e);
        std::process::exit(1);
    }
}
