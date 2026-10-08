---
name: hush-ingest
description: Store a secret in hush from a Bitwarden Send link (or from an item already in the agent's Bitwarden vault) without ever seeing its value. Runs on the agent's smallest model (Claude Code: Haiku) in a separate context that cannot see this conversation, so pass the Send URL, the hush name to store it under, and the email the Send is gated to, if any, as the arguments.
context: fork
model: haiku
background: false
allowed-tools: Bash, Read
argument-hint: <send-url> --name <HUSH_NAME> [--email <addr>]
---

# hush ingest

## Who runs this

Storing a secret is mechanical: the main model decides the name, the smallest model available runs `hush pull`.

- **Claude Code** runs this skill on Haiku in its own context (`context: fork`, `model: haiku` above). The request: $ARGUMENTS
- **Codex**: spawn the custom agent `hush_ingest` (`~/.codex/agents/hush_ingest.toml`, `gpt-6-luna`) with the full request.
- **Grok**: spawn a subagent with role `small` (`grok-build`) with the full request and the steps below.
- **Hermes**: hand the full request and the steps below to `delegate_task` (its children run on `delegation.model`).
- If you are that small agent, or none of these applies, follow the steps below yourself.

## Steps

1. Read the hush skill (`~/.agents/skills/hush/SKILL.md`), sections "When they share a Bitwarden Send link", "Email-gated Sends" and "When the secret is already in the agent's Bitwarden vault", and run the matching `hush pull … --json`.
2. Without a hush name to store it under, return that the name is missing and pull nothing.
3. Never print, echo or read a secret value, never open the vault files, never run `bw` directly.
4. Return the JSON hush printed (`event`, `name`), or its error, and nothing else.
