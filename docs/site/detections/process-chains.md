---
title: D1 · Process chains
description: Hermian's process-chain rules - web servers and databases starting shells, downloads, relays and interpreters, download-and-run chains, execution from /tmp and fileless execution.
---

# D1 · Process chains

D1 judges every program start by its ancestry. A shell is ordinary; a shell
whose ancestor is nginx is how a web shell or a remote code execution shows
itself.

**Services** are processes whose executable is a known web server (nginx,
apache2, httpd, caddy, lighttpd, LiteSpeed, gunicorn, uwsgi, unicorn, puma,
tomcat, traefik, haproxy, varnishd, envoy, php-fpm) or database (mysqld,
mariadbd, postgres, mongod, redis-server, valkey-server, elasticsearch,
clickhouse-server, etcd, influxd, cockroach, cassandra, consul, vault,
memcached). Wrappers in between (`env`, `setsid`, `nohup`, `timeout`, `nice`,
`ionice`, `stdbuf`, `chrt`, `taskset`, `xargs`, `script`, `unbuffer`, `flock`)
are seen through. Other programs in between are named in the title
("… (via perl, awk)").

A D1 alert at HIGH or above **flags** the suspicious part of the chain for ten
minutes: later events from it escalate (see
[Execution from a transient directory inside a flagged chain](#execution-from-a-transient-directory-inside-a-flagged-chain)
and [D5](detections/network)).

### Web server spawned a shell

`HIGH`

**Fires when** a shell (bash, sh, dash, zsh, busybox…) starts with a web
server among its ancestors and no other shell in between.

**Why** Web servers don't start shells in normal operation. This is what
remote code execution through a vulnerable application or an uploaded web
shell looks like.

**Do** Find the request in the access logs at that time; identify the
application component; isolate the host if it isn't expected.

**Tune** PHP's `mail()` runs `sh -c sendmail …` and CGI setups run shells
by design. Allowlist the exact pair, ideally on the immediate parent; an entry
on the wrapper (`fcgiwrap` → `sh`) covers it without allowing every nginx
shell.

```toml
[[allowlist.process_chains]]
parent = "php-fpm8.2"
child  = "sh"
user   = "www-data"
reason = "PHP mail() via sendmail"
```

### Database server spawned a shell

`HIGH`

**Fires when** a shell starts under a database server.

**Why** Databases never need shells. This is exploitation of database
features: UDFs, `COPY … PROGRAM`, `xp_cmdshell`-style primitives.

**Do** Review the database logs and client connections; look for new
functions, extensions or scheduled jobs.

### Web server / Database server spawned a network relay tool

`HIGH`

**Fires when** `nc`, `ncat`, `netcat`, `socat`, `openssl` or `telnet` starts
anywhere under a service, even with a shell in between.

**Why** These open reverse and bind shells. A service has no reason to start
one.

### Web server / Database server spawned a download tool

`HIGH`

**Fires when** `curl`, `wget`, `wget2`, `fetch`, `aria2c` or `axel` starts
under a service with no shell in between.

**Why** Fetching content straight from a service process is the staging step
of most remote code execution chains.

**Tune** An application that legitimately shells out to curl: allowlist the
pair.

### Web server / Database server spawned an interpreter

`LOW`

**Fires when** python, perl, ruby, php, node, java or similar starts as a
**direct** child of a service.

**Why** Applications do this (`php artisan`, `python manage.py`), so it's
logged for context. It's also how injected code gets an interpreter without a
shell.

### Web server shell chain started a download

`HIGH`

**Fires when** a download tool runs somewhere under a shell that itself
descends from a web server.

**Why** The web shell is fetching its next stage. Look for the D5 connection
alert from the same chain for the destination.

### Web server chain downloaded and executed remote content

`CRITICAL`

**Fires when** under web server → shell, something runs that was just
downloaded: a child of the downloader (`curl … | sh`), or a payload started by
the same shell within two minutes of a download (`curl -o x; ./x`). Payloads
are shells, interpreters, or binaries outside system directories.

**Why** Web server, shell, downloader, execution: this exact sequence is the
signature of remote code execution.

**Do** Isolate the host unless it's known activity; keep the file and the
process memory; find the entry point in the access logs.

### Execution from a transient directory inside a flagged chain

`CRITICAL`

**Fires when** a program runs from `/tmp`, `/dev/shm` or `/var/tmp` in a chain
flagged by D1 in the last ten minutes.

**Why** A suspicious chain is now running its own tools from a staging
directory.

### Unattended execution from a transient directory

`HIGH`

**Fires when** a program runs from `/tmp`, `/dev/shm` or `/var/tmp` (checked
on the executable and on `argv[0]`), with no interactive session involved and
no package or config manager in the chain.

**Why** Installed software doesn't live there. Attackers stage tools there
because those directories are always writable. On a perfctl-infected host
this fired for the miner's `/tmp/.perf.c/sh` within seconds.

**Tune** A legitimate updater that stages in `/tmp`:

```toml
[[allowlist.binaries]]
path   = "/tmp/app-update/*"
reason = "Vendor updater stages here"
```

### Binary executed from a transient directory

`LOW`

**Fires when** the same happens from an interactive session or under a
package or config manager.

**Why** Installers and builds do it legitimately. Logged for the record.

### Execution from a deleted file

`HIGH`

**Fires when** a *new* program starts from an executable that's already been
deleted from disk.

**Why** Loading a payload and unlinking it leaves nothing to inspect. Package
upgrades replace binaries under running processes, but that shows on
processes already running, never on a fresh start.

**Do** Treat the host as compromised; capture the process memory from
`/proc/<pid>/` before killing it; find the loader in the chain.

### Fileless execution from memory (memfd)

`HIGH`

**Fires when** a program starts from an anonymous in-memory file
(`memfd_create`).

**Why** The payload never touches the disk: a classic fileless technique.

## Limits

D1 sees program starts. Code that runs inside an existing process without
starting a new program (an interpreter's `eval`, injected shellcode) isn't a
process chain. Short-lived processes can be missed when the kernel lacks eBPF
and Hermian polls `/proc`.
