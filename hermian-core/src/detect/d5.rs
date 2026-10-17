//! D5 - Anomalous network behaviour in context.

use crate::alert::Finding;
use crate::detect::{is_private_ip, Ctx};
use crate::events::{ConnectEvent, DetectionId, ListenerEvent, Severity};
use crate::proctree::{role_of, Role};

/// Ports where a "first connection" is almost always benign (DNS, NTP, DHCP).
const INFRA_PORTS: &[u16] = &[53, 123, 67, 68, 5353];

pub fn evaluate_connect(ev: &ConnectEvent, ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    // chain.first() is PID 1 on a real host (the daemon seeds the tree from
    // /proc), so it can't stand in for "who connected". Use the nearest web
    // server in the chain, and the connecting process itself as the connector.
    let chain = ctx.tree.chain_of(ev.pid);
    let web_server = chain
        .iter()
        .rev()
        .find(|p| role_of(&p.comm, &p.exe) == Role::WebServer);
    let connector_key = connector_key(&connector_exe(ctx.tree, ev.pid, &ev.comm), ev.uid);
    let is_external = !is_private_ip(ev.daddr);
    let dest_allowed = ctx.allowlist.destination_allowed(ev.daddr);
    let dest = format!("{}:{}", ev.daddr, ev.dport);

    if dest_allowed {
        return findings;
    }

    let flagged = ctx.has_recent_flag(
        ev.pid,
        crate::detect::FLAG_WINDOW_SECS,
        Some(DetectionId::D1),
    );
    if flagged {
        findings.push(
            Finding::new(
                DetectionId::D5,
                Severity::High,
                "Outbound connection from a flagged process chain",
                // Per program, not per address: a miner or proxy calling 40
                // addresses is one incident, and the summary lists them.
                &format!("d5|connect-flagged|{}", connector_key),
            )
            .varies("Destinations", &dest)
            .what(format!(
                "{} (pid {}) connected to {} within ten minutes of its chain being flagged by D1.",
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

    // Only skip infra ports after the flagged-chain check: a web shell
    // calling out to attacker:53 is exactly the case we mustn't drop. And
    // only to the LAN or to servers seen while learning: "port 53 to
    // anywhere" was a free pass for DNS-port C2 to a fresh address.
    if INFRA_PORTS.contains(&ev.dport)
        && (!is_external
            || !ctx.baseline.can_judge_novelty()
            || ctx.baseline.dest_is_known(ev.daddr))
    {
        return findings;
    }

    if let Some(web) = web_server.filter(|_| {
        is_external && ctx.baseline.can_judge_novelty() && !ctx.baseline.dest_is_known(ev.daddr)
    }) {
        findings.push(
            Finding::new(
                DetectionId::D5,
                Severity::High,
                "Web server connected to a new external destination",
                &format!("d5|web-new-dest|{}", ev.daddr),
            )
            .what(format!(
                "{} (under {}) connected to {}, a destination never seen before.",
                ev.comm, web.comm, dest
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

    if ctx.baseline.can_judge_connectors(ctx.now)
        && !ctx.baseline.connector_is_known(&connector_key)
    {
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
                ev.comm,
                ctx.user_name(ev.uid).unwrap_or("unknown user"),
                dest
            ))
            .chain(ctx.chain_nodes(ev.pid))
            .fact("Destination", &dest)
            .why(
                "Hermian learned which programs use the network during the baseline period. A new \
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

/// The connecting process's own executable, or its comm if the tree doesn't
/// know it. See [`crate::baseline::CONNECTOR_SCHEME`].
pub fn connector_exe(tree: &crate::proctree::ProcessTree, pid: u32, comm: &str) -> String {
    tree.get(pid)
        .map(|p| p.exe.as_str())
        .filter(|e| !e.is_empty())
        .unwrap_or(comm)
        .to_string()
}

pub fn evaluate_listener(ev: &ListenerEvent, ctx: &Ctx) -> Vec<Finding> {
    let flagged = ev.pid != 0
        && ctx.has_recent_flag(
            ev.pid,
            crate::detect::FLAG_WINDOW_SECS,
            Some(DetectionId::D1),
        );
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
        &format!(
            "d5|listener|{}|{}|{}|{}",
            ev.proto, ev.addr, ev.port, ev.comm
        ),
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
