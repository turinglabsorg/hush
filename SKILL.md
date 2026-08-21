---
name: hush
description: "Agent-blind secrets. Ingest from Signal by name, never print values, inject via hush run. Use when the user mentions hush, hush:NAME, Signal secrets, or says they put a secret in chat/Note to Self."
---

# Hush

Secrets live in an age vault at `~/.hush`. The agent never sees plaintext.

## Non-negotiables

- Never paste, quote, log, or re-ask for a secret value.
- Never run `signal-cli`, never read `~/.hush/identity` or `~/.hush/vault/*.age`.
- Never invent `hush show` / `hush get`. Those commands do not exist.
- If the user pastes a secret in **this** conversation, do not store it from here. Tell them to send it on Signal (Note to Self), then pull.

## When they say the secret is on Signal / "in chat"

They send the value from the phone. You only get the **name**.

```bash
hush pull --name <name> --json
```

Report the JSON (`event`, `name`, `sender`). Then stop. Do not inspect the vault files.

If they already used `hush put NAME` in the Signal message, this is enough:

```bash
hush pull --json
```

If pull says nothing was waiting, ask them to send it again on Signal and retry. Do not ask them to paste it here.

## Use a stored secret

```bash
hush run --name <name> --env <ENV_VAR> -- <command>...
```

The child process gets the env var. You only see the command's own output.

```bash
hush list --json
hush info <name> --json
hush rm <name>
hush doctor --json
```

If the `hush` binary is missing:

```bash
curl -fsSL https://raw.githubusercontent.com/turinglabsorg/hush/main/install.sh | sh -s -- --agent-skill --path-link
```

## Setup (human, not you)

If `hush doctor --json` reports missing identity or unlinked Signal, tell the user to run:

```bash
hush init
hush signal link
```

Scan the QR from Signal → Settings → Linked devices. Then they send Note to Self and you `hush pull`.

Do not run `hush listen` or `hush signal link` unless they explicitly ask. Pull is the agent path.
