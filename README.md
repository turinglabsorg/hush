# hush

Agent-blind secrets for humans and coding agents. The value arrives over **Signal**, is stored encrypted with **age**, and is used by **name**. The CLI never prints plaintext.

MIT. Open source at [github.com/turinglabsorg/hush](https://github.com/turinglabsorg/hush).

```
phone (Note to Self)  →  hush pull --name stripe-prod  →  ~/.hush/vault/stripe-prod.age
agent chat: "use hush:stripe-prod"
hush run --name stripe-prod --env STRIPE_API_KEY -- curl ...
```

There is no Signal bot. Hush is a **linked device** on your existing account (`signal-cli`), the same idea as Signal Desktop.

## Install

Needs a Rust toolchain and [signal-cli](https://github.com/AsamK/signal-cli) on `PATH` (or `HUSH_SIGNAL_CLI`).

```bash
git clone https://github.com/turinglabsorg/hush.git
cd hush
./install.sh --from-source --agent-skill --path-link
```

Or:

```bash
cargo install --git https://github.com/turinglabsorg/hush --locked
```

Then:

```bash
brew install signal-cli   # or install signal-cli another way
hush init
hush signal link          # QR → Signal → Settings → Linked devices
```

## Deposit

From the phone, send **Note to Self** with just the secret (or `hush put NAME` then the secret on the next lines).

Then, in the agent chat, only the name:

> I put the secret in Signal, store it as `stripe-prod`

The agent runs:

```bash
hush pull --name stripe-prod --json
```

`hush pull` calls `signal-cli receive` internally, encrypts, writes the vault, and prints **metadata only**:

```json
{"event":"stored","name":"stripe-prod","sender":"self","replaced":false}
```

`hush listen` is the optional long-running variant. Agents should use `pull`.

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

Override the home directory with `--home` or `HUSH_HOME`.

## Threat model

Hush stops secrets from entering **agent transcripts**. It does not protect you from a process running as the same OS user with the identity file. `hush run` is the supported use path; reading vault ciphertext is expected, reading identity + decrypting is the bypass.

Default allowlist is `self` (Note to Self / your own number). Add senders with `hush signal allow +E164`.

## Development

```bash
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
```

## License

[MIT](LICENSE). Copyright (c) 2026 Turing Labs.

`signal-cli` is a separate AGPL program; hush talks to it as an external process and does not link it.
