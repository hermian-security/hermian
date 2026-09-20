//! D5 - Anomalous network behaviour in context.

use crate::alert::Finding;
use crate::detect::{is_private_ip, Ctx};
use crate::events::{ConnectEvent, DetectionId, ListenerEvent, Severity};
use crate::proctree::{role_of, Role};

/// Ports where a "first connection" is almost always benign (DNS, NTP, DHCP).
const INFRA_PORTS: &[u16] = &[53, 123, 67, 68, 5353];

pub fn evaluate_connect(ev: &ConnectEvent, ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    if INFRA_PORTS.contains(&ev.dport) {
        return findings;
    }
    let chain = ctx.tree.chain_of(ev.pid);
    let root = chain.first();
    let root_role = root
        .map(|p| role_of(&p.comm, &p.exe))
        .unwrap_or(Role::Unknown);
    let connector_key = connector_key(root.map(|p| p.exe.as_str()).unwrap_or(&ev.comm), ev.uid);
    let is_external = !is_private_ip(ev.daddr);
    let dest_allowed = ctx.allowlist.destination_allowed(ev.daddr);
    let dest = format!("{}:{}", ev.daddr, ev.dport);

    if dest_allowed {
        return findings;
    }

    let flagged = ctx.has_recent_flag(ev.pid, 120, Some(DetectionId::D1));
    if flagged {
        findings.push(
            Finding::new(
                DetectionId::D5,
                Severity::High,
                "Outbound connection from a flagged process chain",
                &format!("d5|connect-flagged|{}|{}", ev.comm, ev.daddr),
            )
            .what(format!(
                "{} (pid {}) connected to {} within two minutes of its chain being flagged by D1.",
                ev.comm, ev.pid, dest
            ))
            .chain(ctx.chain_nodes(ev.pid))
            .fact("Destination", &dest)
            .why(
                "A process chain already flagged for suspicious execution reaching out to the \
                 network is the command-and-control or exfiltration step of an intrusion.",
            )
            .actions([
                "Correlate the destination with the earlier D1 alert.",
                "Block the destination at the firewall if unknown.",
                "Investigate the chain end to end.",
            ]),
        );
        return findings;
    }

    if root_role == Role::WebServer
        && is_external
        && ctx.baseline.can_judge_novelty()
        && !ctx.baseline.dest_is_known(ev.daddr)
    {
        findings.push(
            Finding::new(
                DetectionId::D5,
                Severity::High,
                "Web server connected to a new external destination",
                &format!("d5|web-new-dest|{}", ev.daddr),
            )
            .what(format!(
                "{} connected to {}, a destination never observed during the baseline period.",
                root.map(|p| p.comm.as_str()).unwrap_or(&ev.comm),
                dest
            ))
            .chain(ctx.chain_nodes(ev.pid))
            .fact("Destination", &dest)
            .why(
                "Web servers talk to a stable set of backends and APIs. A brand-new external \
                 destination can be a web shell calling home or a payload fetching its next stage.",
            )
            .actions([
                "Check the access logs for the request that coincides with this connection.",
                "Verify the destination is a legitimate dependency.",
                "Add it to allowlist.destinations if it is; block it if not.",
            ]),
        );
        return findings;
    }

    if ctx.baseline.can_judge_novelty() && !ctx.baseline.connector_is_known(&connector_key) {
        let severity = if is_external {
            Severity::Low
        } else {
            Severity::Info
        };
        findings.push(
            Finding::new(
                DetectionId::D5,
                severity,
                "First outbound connection from a program",
                &format!("d5|first-connect|{}", connector_key),
            )
            .what(format!(
                "{} ({}) made its first observed outbound connection, to {}.",
                root.map(|p| p.comm.as_str()).unwrap_or(&ev.comm),
                ctx.user_name(ev.uid).unwrap_or("unknown user"),
                dest
            ))
            .chain(ctx.chain_nodes(ev.pid))
            .fact("Destination", &dest)
            .why(
                "HERMIAN learned which programs use the network during the baseline period. A new \
                 network-using program is worth a glance, though not on its own evidence of \
                 compromise.",
            )
            .actions([
                "Check whether this program legitimately needs network access.",
                "Add it to the allowlist if expected.",
            ]),
        );
    }
    findings
}

pub fn connector_key(exe: &str, uid: u32) -> String {
    format!("{}|{}", exe, uid)
}

pub fn evaluate_listener(ev: &ListenerEvent, ctx: &Ctx) -> Vec<Finding> {
    let flagged = ev.pid != 0 && ctx.has_recent_flag(ev.pid, 300, Some(DetectionId::D1));
    let owner_role = ctx
        .tree
        .get(ev.pid)
        .map(|p| role_of(&p.comm, &p.exe))
        .unwrap_or(Role::Unknown);
    let from_transient = ctx
        .tree
        .get(ev.pid)
        .map(|p| crate::events::is_suspicious_exec_dir(&p.exe))
        .unwrap_or(false);
    let bound_everywhere = ev.addr.is_unspecified();
    let high_port = ev.port >= 1024;
    let addr = format!("{}:{}", ev.addr, ev.port);

    let (severity, title) = if flagged || from_transient {
        (
            Severity::High,
            "New listener opened by a suspicious process",
        )
    } else if owner_role == Role::Shell
        || (owner_role == Role::Interpreter && bound_everywhere && high_port)
    {
        (
            Severity::Low,
            "New listener opened by a shell or interpreter",
        )
    } else {
        (Severity::Info, "New listening port")
    };

    vec![Finding::new(
        DetectionId::D5,
        severity,
        title,
        &format!("d5|listener|{}|{}|{}", ev.proto, ev.port, ev.comm),
    )
    .what(format!(
        "{} (pid {}) started listening on {} ({}).",
        ev.comm, ev.pid, addr, ev.proto
    ))
    .chain(if ev.pid != 0 {
        ctx.chain_nodes(ev.pid)
    } else {
        Vec::new()
    })
    .fact("Listener", &addr)
    .why(if severity >= Severity::High {
        "A process already implicated by another detection, or running from a transient \
         directory, has opened a port. That is how bind shells and reverse proxies for \
         attacker access appear."
    } else {
        "New listeners change the host's exposure. Most are intentional service changes; they \
         are logged so a later investigation has the timeline."
    })
    .actions(if severity >= Severity::High {
        vec![
            "Identify the process and the chain that opened the port.",
            "Block the port and terminate the process if unauthorized.",
        ]
    } else {
        vec!["Verify the new service is intentional and firewalled appropriately."]
    })]
}
