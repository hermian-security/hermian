//! HERMIAN detection engine.
//!
//! This crate is deliberately free of I/O and platform dependencies: it turns a
//! stream of [`Event`]s into [`Alert`]s and nothing else. The `hermian` binary
//! crate owns eBPF, `/proc`, inotify and delivery.

pub mod alert;
pub mod allowlist;
pub mod baseline;
pub mod config;
pub mod dedup;
pub mod detect;
pub mod engine;
pub mod events;
pub mod proctree;
pub mod selftest;

pub use alert::{
    escape_untrusted, render, render_alert, Alert, ChainNode, Fact, Finding, RefGen, Theme,
};
pub use allowlist::Allowlist;
pub use baseline::Baseline;
pub use config::{Config, DEFAULT_CONFIG_TOML};
pub use engine::{Counters, Engine, EngineFlaggedChain as FlaggedChain};
pub use events::{
    AuthEvent, AuthResult, ConnectEvent, DetectionId, Event, ExecEvent, FileEvent, FileKind,
    ListenerEvent, ProcInfo, PtraceEvent, Severity, WriterInfo,
};
pub use proctree::{role_of, ProcessTree, Role};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
