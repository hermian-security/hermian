# Testing the Hermian beta

Everything you need to test the beta, in one place. It takes about 10
minutes to set up, then two weeks of running the server normally.

What we ask: install it, use the server as usual for two weeks, and send
one report at the end. What you get: a watched server, a direct line to us,
and your name on the early testers wall.


## Before you start

- A Linux server with systemd: a VPS, a homelab box, a quiet production
  host. Root access.
- Kernel 5.4 or newer (5.8+ for full coverage). amd64 or arm64.
- Ubuntu 22.04 is the tested system. Others should work, and that's
  exactly what we want to find out.
- No container or Kubernetes node: Hermian watches the host, not pods.


## 1. Install (2 minutes)

    curl -fsSL https://hermian.me/install.sh | sudo sh

The script verifies the download before installing. On Debian and Ubuntu it
also adds apt.hermian.me, so `sudo apt upgrade` brings each new beta.


## 2. Get alerts on your phone (5 minutes)

Telegram is the quickest:

1. Message @BotFather in Telegram, send `/newbot`, copy the token.
2. Send your new bot any message, then open
   https://api.telegram.org/bot<TOKEN>/getUpdates and copy the number
   after `"chat":{"id":`.
3. Edit /etc/hermian/config.toml:

       [notifications]
       channels = ["journald", "file", "telegram"]

       [notifications.telegram]
       bot_token = "123456:ABC..."
       chat_id = "123456789"

4. Save. Hermian picks the change up on its own, and tells you the config
   changed: that first alert is expected. Then:

       sudo hermian notify-test

Email, Slack, Discord and webhooks work too; the README has the settings.


## 3. Check it works (1 minute)

    sudo hermian status    # PROTECTED, coverage on eBPF or inotify
    sudo hermian test      # 9 simulated attacks, all detected

Neither command touches the system: the test runs inside Hermian.


## 4. Use the server normally for two weeks

Nothing else to do. Hermian stays quiet unless something looks like a
compromise. When an alert arrives:

    sudo hermian show <ref>    # the full story: chain, evidence, risk

If it was you (a deploy, an admin task), that's a false positive and the
most useful thing you can tell us. Note the reference and what you were
doing.


## 5. Send your report (2 minutes)

    sudo hermian report

Paste the output into the beta report form:
https://github.com/hermian-security/hermian/issues/new?template=beta-report.yml

The report holds counts, versions and coverage. No host name, addresses,
users, paths or commands.


## 6. Join the wall (optional)

Once your report is in, add yourself to "Early testers" in the README. The
steps are right under the list.


## Questions, problems, false positives

Open an issue: https://github.com/hermian-security/hermian/issues
Or write to contact@hermian.me.

A security problem in Hermian itself goes to SECURITY.md, privately.


## Updates and removal

New betas come through `sudo apt upgrade` (Debian, Ubuntu) or by running
the install line again. To remove everything:

    sudo hermian uninstall
