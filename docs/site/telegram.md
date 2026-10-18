---
title: Telegram
description: Send Hermian alerts to a Telegram chat or group - create the bot, find the chat id, topics, sounds, and response buttons.
---

# Telegram

Telegram is the quickest way to get alerts on a phone, and the only channel
with [response buttons](response#telegram-buttons).

## Set it up

1. In Telegram, message [@BotFather](https://t.me/BotFather): `/newbot`, pick a
   name and a username ending in `bot`. Copy the token.
2. Send any message to your new bot. For a group: add the bot to the group,
   then send a message that **mentions** it (`@your_bot hi`): bots only see
   mentions and commands in groups.
3. Read the chat id:
   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" \
     | grep -o '"chat":{"id":[0-9-]*\|"message_thread_id":[0-9]*'
   ```
   A private chat's id is your own user id; a group's is negative
   (`-1001234567890`).
4. Configure:
   ```toml
   [notifications]
   channels = ["journald", "file", "telegram"]

   [notifications.telegram]
   bot_token = "123456789:AAH..."
   chat_id = "-1001234567890"     # in quotes
   ```
5. `sudo hermian notify-test -c telegram`.

## Options

| Setting | Default | What it does |
|---|---|---|
| `bot_token` | | The token from @BotFather |
| `chat_id` | | The chat or group, in quotes |
| `message_thread_id` | unset | A topic id, for groups with Topics: each server can post into its own |
| `silent_below_critical` | `true` | Only CRITICAL makes a sound; HIGH arrives silently |
| `timeout_secs` | `10` | HTTP timeout (1 to 300) |
| `actions` | `false` | Response buttons under alerts that offer them |
| `allowed_user_ids` | `[]` | Who may press them: numeric Telegram user ids (ask @userinfobot) |
| `action_ttl_mins` | `15` | How long a button stays valid (1 to 1440) |

## The message

```text
◉◉◉◉  CRITICAL · Process chain
Web server chain ran downloaded code

┃ nginx started a shell that downloaded a file and is now running it as
┃ www-data.

host   web-01
chain  nginx › sh › curl
rule   D1 · Suspicious process chain
time   6 Oct 2026 · 03:14 UTC

┃ Risk · Next steps   (tap to expand)

hermian show HER-2026-1006-415
```

The meter counts up with severity (`◉○○○` INFO to `◉◉◉◉` CRITICAL). The risk
and next steps sit in a collapsed quote, so the push stays short.

## Several servers

Many hosts can send through one bot into one group. Buttons are the exception:
presses are fetched with `getUpdates`, and only one process can read a bot's
updates, so each host with buttons needs a bot of its own. A second host on the
same bot shows `HTTP 409` in `hermian status`. [Several servers](fleet)
explains the setup.

## Security

The token gives control of the bot: keep `/etc/hermian/config.toml` root-only
(0600, as `hermian enable` creates it). Messages pass through Telegram's
servers; use [`content = "minimal"`](notifications#keeping-alerts-in-house) if
alert details shouldn't.
