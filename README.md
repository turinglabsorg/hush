# hush

Agent-blind secrets for humans and coding agents. The value is shared over **Bitwarden** (Send link or vault item), is stored encrypted with **age**, and is used by **name**. The CLI never prints plaintext.

MIT. Open source at [github.com/turinglabsorg/hush](https://github.com/turinglabsorg/hush).

```
bitwarden Send link  →  hush pull --name stripe-prod --send <url>  →  ~/.hush/vault/stripe-prod.age
agent chat: "use hush:stripe-prod"
hush run --name stripe-prod --env STRIPE_API_KEY -- curl ...
```

The agent gets its own Bitwarden account (its own vault, optionally via `BITWARDENCLI_APPDATA_DIR`). Humans share secrets with it through **Bitwarden Send**, or through vault items (shared org collection) named `hush put NAME`.

## Install

Install the latest GitHub Release (SHA-256 verified; cosign if present):

```bash
curl -fsSL https://raw.githubusercontent.com/turinglabsorg/hush/main/install.sh | sh
```

With the agent skill and a PATH symlink:

```bash
curl -fsSL https://raw.githubusercontent.com/turinglabsorg/hush/main/install.sh | sh -s -- --agent-skill --path-link
```

Pin a version with `--version v0.1.0`. Build from a checkout with `--from-source`.

Needs the [Bitwarden CLI](https://bitwarden.com/help/cli/) (`bw`) on `PATH` (or `HUSH_BW_BIN`).

Then:

```bash
bw login --apikey   # or `bw login` interactively; `bw config server <url>` first if self-hosted
bw unlock           # export the printed BW_SESSION
export BW_SESSION="..."
hush init
hush doctor --json  # must report ok
```

## Deposit

**Option A — Bitwarden Send (recommended).** Create a text Send with the secret, then in the agent chat paste only the Send **URL** (URLs are not secret) plus the name:

> Store this as `stripe-prod`: https://vault.bitwarden.com/#/send/...

The agent runs:

```bash
hush pull --name stripe-prod --send <url> --json
```

For a password-protected Send, hand the password over out of band and use `--passwordenv VAR` or `--passwordfile PATH` (never a literal `--password` on the command line). `hush pull` receives the Send, encrypts, writes the vault, and prints **metadata only**:

```json
{"event":"stored","name":"stripe-prod","sender":"self","replaced":false}
```

**Option B — vault item.** Add an item to the agent's vault (or a shared org collection) named exactly `stripe-prod` (secret in the password or notes field), or named `hush put stripe-prod`. Then:

```bash
hush pull --name stripe-prod --json
hush pull --json   # one-shot scan for all `hush put NAME` items
```

Add `--consume` to trash the vault item after it is stored. `hush listen` is the polling daemon variant (human use). Agents should use `pull`.

## Use

```bash
hush list --json
hush run --name stripe-prod --env STRIPE_API_KEY -- \
  curl https://api.stripe.com/v1/charges
```

There is no `show` / `get`. Decrypt happens in memory and is injected into the child environment.

## Layout

```
~/.hush/config.json
~/.hush/identity          # age X25519, mode 600
~/.hush/vault/<name>.age
~/.hush/vault/<name>.meta.json
```

Override the home directory with `--home` or `HUSH_HOME`. Point at another `bw` binary with `HUSH_BW_BIN`. `bw` auth (`BW_SESSION`, `BITWARDENCLI_APPDATA_DIR`) is inherited from the environment.

## Threat model

Hush stops secrets from entering **agent transcripts**: `bw` output is piped, never printed. It does not protect you from a process running as the same OS user with the identity file. `hush run` is the supported use path; reading vault ciphertext is expected, reading identity + decrypting is the bypass. Never run `bw get` / `bw send receive` by hand in front of an agent — the value would land in the transcript.

## Development

```bash
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
```

Integration tests stub the Bitwarden CLI with `tests/fixtures/fake-bw.sh` (via `HUSH_BW_BIN` + `FAKE_BW_DIR`).
Live end-to-end (real account + server) was verified manually: Send receive → `pull --send`,
vault item → `pull` scan, `--consume` trash, `listen` poll, and `run` injection (compared by hash, never printed).

## License

[MIT](LICENSE). Copyright (c) 2026 Turing Labs.
