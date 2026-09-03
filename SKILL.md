---
name: hush
description: "Agent-blind secrets. Ingest from Bitwarden by name, never print values, inject via hush run. Use when the user mentions hush, hush:NAME, Bitwarden secrets, shares a Bitwarden Send link, or whenever ANY task needs a secret (API key, token, password)."
---

# Hush

Secrets live in an age vault at `~/.hush`. The agent never sees plaintext.

## Secrets policy (highest priority)

The ONLY way for you to ask for, receive, read, or use a secret is hush.

- If a task needs a credential you do not have stored: do NOT ask the user to paste or tell you the value. Ask them to share it via Bitwarden Send (or a `hush put NAME` vault item) and give you only the NAME (Send URLs are fine, they are not secret).
- Do NOT read secret values from files, environment output, chat history, logs, or tool results in order to use them. If a secret value appears in front of you anyway, do NOT repeat, quote, or log it: route it into hush (tell the user to share it via Send) and continue by name.
- A secret value must never appear in your messages, tool arguments (except `hush run`'s child command, which never prints it), or any file you write.

## Non-negotiables

- Never paste, quote, log, or re-ask for a secret value.
- Never run `bw get` / `bw send receive` yourself, never read `~/.hush/identity` or `~/.hush/vault/*.age`.
- Never invent `hush show` / `hush get`. Those commands do not exist.
- Never pass a literal Send password on a command line. Use `--passwordenv VAR` or `--passwordfile PATH` so the password never lands in transcripts or process lists.
- If the user pastes a secret in **this** conversation, do not store it from here. Tell them to share it via Bitwarden Send (or a `hush put NAME` vault item), then pull.

## When they share a Bitwarden Send link

They create a Send in Bitwarden and paste only the **URL** (URLs are not secret). You only get the **name**.

```bash
hush pull --name <name> --send <url> --json
```

For a password-protected Send (password reaches you out of band, never in chat if avoidable):

```bash
hush pull --name <name> --send <url> --passwordenv BW_SEND_PW --json
```

Report the JSON (`event`, `name`). Then stop. Do not inspect the vault files.

## When the secret is already in the agent's Bitwarden vault

The agent has its own Bitwarden account (or shared org collection). A vault item named exactly `<name>`, or an item named `hush put <name>` (secret in the password or notes field), is ingested with:

```bash
hush pull --name <name> --json
hush pull --json   # one-shot scan for all `hush put NAME` items
```

Add `--consume` to trash the vault item after it is stored.

## Use a stored secret

Always pass `--redact`: child output is piped through a filter that
replaces the secret with `[redacted by hush]`, so even a command that
echoes its own input cannot leak it into the transcript.

```bash
hush run --name <name> --env <ENV_VAR> --redact -- <command>...
```

The child process gets the env var (and nothing else secret-bearing:
`BW_SESSION` and friends are never inherited). You only see the command's
filtered output.

```bash
hush list --json
hush info <name> --json
hush rm <name>
hush doctor --json
hush bitwarden status --json
```

If the `hush` binary is missing:

```bash
curl -fsSL https://raw.githubusercontent.com/turinglabsorg/hush/main/install.sh | sh -s -- --agent-skill --path-link
```

## Setup (human, not you)

The agent machine needs the Bitwarden CLI logged in and unlocked:

```bash
bw login --apikey        # automation-friendly; or `bw login` interactively
bw unlock                # export the printed BW_SESSION
export BW_SESSION="..."
hush init
# Block direct `bw` for the agent: every `bw ...` call then fails
# with a pointer back to hush instead of printing secrets.
hush agent-shim --dir ~/.hush/agent-bin   # put FIRST in the agent's PATH
hush doctor --json       # must report ok
```

For a self-hosted server, the human runs `bw config server <url>` first. An isolated agent account can use `BITWARDENCLI_APPDATA_DIR` for its own `bw` profile.

Do not run `hush listen` unless they explicitly ask. Pull is the agent path.
