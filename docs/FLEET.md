# Running Hermian on several servers

How to put Hermian on 5, 20 or 50 servers that all report into one Telegram
group. There's no central server to run: every host works on its own, and
the group is where you see them all.

Time: about 15 minutes once, then a minute or two per server.

## The setup in short

- **One Telegram bot and one group for every server.** You don't need a bot
  per server: many hosts can send through the same bot at the same time.
- **One config file**, the same everywhere, except each host's name.
- **Buttons (Block, Disconnect) only where you need them**, each of those
  hosts with a bot of its own. [Why](#buttons-on-several-servers).
- **Updates through the APT repository**, optionally automatic.

---

## 1. The bot and the group (once)

1. In Telegram, message [@BotFather](https://t.me/BotFather): `/newbot`,
   pick a name (e.g. *Hermian alerts*) and a username ending in `bot`. Copy
   the token it gives you.
2. Create a group (e.g. *Servers*), add the people who should see alerts,
   then add the bot to it.
3. Optional: in the group's settings turn on **Topics**, and create one per
   environment (*prod*, *staging*, *clients*…). Each server can then post into
   its own topic.
4. In the group, send a message that **mentions the bot** (`@your_bot hi`).
   Bots only see commands and mentions in groups, so a plain message won't
   show up. With topics, do it once in each topic. Then read the ids:

   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" \
     | grep -o '"chat":{"id":-[0-9]*\|"message_thread_id":[0-9]*'
   ```

   The chat id is negative (e.g. `-1001234567890`); each topic has its own
   `message_thread_id`.

## 2. One config for every server

Write it once, on your own machine, as `hermian-fleet.toml`. `HOSTNAME` and
`TOPIC` are placeholders the rollout in step 3 fills in. Settings you leave
out keep their defaults (the full list, with comments, is in
`/etc/hermian/config.toml` on any installed host).

```toml
[general]
hostname = "HOSTNAME"            # the name alerts show, e.g. "web-prod-1"

[notifications]
channels = ["journald", "file", "telegram"]
min_severity = "HIGH"

[notifications.telegram]
bot_token = "123456789:AAH..."   # the one bot from step 1
chat_id = "-1001234567890"       # the group
message_thread_id = TOPIC        # remove this line if you don't use topics
silent_below_critical = true
actions = false                  # buttons: see "Buttons on several servers"

[response]
management_cidrs = ["203.0.113.0/24"]   # where you manage servers from

# Exceptions every server shares, each with a reason.
[[allowlist.ssh_sources]]
source = "203.0.113.0/24"
reason = "Office and VPN"
```

Keep the file private: it holds the bot token.

## 3. Roll it out

You need SSH access as root to every server. List them with the name and
topic each should use:

```text
# hosts.txt: address  name  topic
203.0.113.10  web-prod-1  2
203.0.113.11  web-prod-2  2
198.51.100.5  db-prod-1   2
192.0.2.20    staging-1   4
```

The config goes on each server **before** Hermian is installed: Hermian
starts with a config it finds instead of writing its default one, so there's
no restart and no "configuration changed" alert.

### With a shell loop

Set `VER` to the newest release (the README's install line, or the
[releases page](https://github.com/hermian-security/hermian/releases)).

```bash
VER=v0.1.0-beta.11
grep -v '^#' hosts.txt | while read -r addr name topic; do
  [ -n "$addr" ] || continue
  echo "== $name ($addr)"
  sed -e "s/HOSTNAME/$name/" -e "s/TOPIC/$topic/" hermian-fleet.toml \
    | ssh root@"$addr" "mkdir -p /etc/hermian && install -m 600 /dev/stdin /etc/hermian/config.toml" \
    && ssh -n root@"$addr" "curl -fsSL https://github.com/hermian-security/hermian/releases/download/$VER/install.sh | sh && hermian notify-test"
done
```

Each server gets its config, installs Hermian (and the APT repository) and
sends a test message. One per server should arrive in the group, each with
its own name.

To change the config later, push the file the same way (the first `ssh`
line): valid changes reload by themselves, and raise a "configuration
changed" alert so you know it landed.

### With Ansible

```yaml
- hosts: hermian
  become: true
  tasks:
    - name: Config (before the install, so Hermian starts with it)
      ansible.builtin.template:
        src: hermian-fleet.toml.j2   # HOSTNAME -> {{ hermian_name }}, TOPIC -> {{ hermian_topic }}
        dest: /etc/hermian/config.toml
        owner: root
        mode: "0600"

    - name: Install Hermian
      ansible.builtin.shell: >
        curl -fsSL https://github.com/hermian-security/hermian/releases/download/{{ hermian_version }}/install.sh | sh
      args:
        creates: /usr/bin/hermian
```

Set `hermian_version` (e.g. `v0.1.0-beta.11`), `hermian_name` and
`hermian_topic` in your inventory. A config change on an installed host
reloads by itself, so no restart handler is needed.

## 4. Updates

The installer adds the signed APT repository on Debian and Ubuntu, so
`apt upgrade` updates Hermian with everything else. To have it happen on its
own with `unattended-upgrades`, allow the repository once per server:

```bash
echo 'Unattended-Upgrade::Origins-Pattern:: "origin=Hermian Security";' \
  | sudo tee /etc/apt/apt.conf.d/51hermian-unattended
```

Read the release notes before big jumps all the same: they list any
one-time steps.

## 5. Checking on the fleet

Every server answers for itself. A quick round:

```bash
grep -v '^#' hosts.txt | while read -r addr name _; do
  [ -n "$addr" ] || continue
  printf '%-14s %s\n' "$name" "$(ssh -n root@"$addr" 'echo $(hermian --version) $(systemctl is-active hermian)')"
done
```

`sudo hermian status` on a host shows coverage and delivery problems, and
`sudo hermian report` its last week of alerts by rule: start with the
noisiest server. A server whose daemon stops still tells you: the dead-man
switch on each host alerts.

## Buttons on several servers

The buttons under SSH login alerts (Block, Disconnect session…) need the
host to *listen* to its bot. Telegram hands each button press to only one
listener, so when several hosts with `actions = true` share a bot, a press
often reaches the wrong server: it answers "expired" and the right one never
sees it. The hosts also knock each other off (`hermian status` shows an
HTTP 409 polling error).

So:

- **Most servers:** keep `actions = false`. Alerts work the same; you act
  over SSH.
- **The few where you want buttons** (a bastion, the server you're paged
  for most): give each one **its own bot**. In @BotFather that's `/newbot`
  again, about a minute each; add every bot to the same group. Then on that
  host only:

  ```toml
  [notifications.telegram]
  bot_token = "its own token"
  actions = true
  allowed_user_ids = [123456789]   # who may press them (ask @userinfobot)
  ```

  and run `sudo hermian enable` once there (it grants the firewall and kill
  capabilities the buttons use).

## Removing a server

On it: `sudo hermian uninstall` (or `sudo apt purge hermian`). Then take it
out of `hosts.txt`.
