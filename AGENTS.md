# Hush

Rust CLI + agent skill. Secrets are ingested from Signal (`hush pull` / `hush listen`), stored with age, and used with `hush run --name`. The binary must not print plaintext.

- Config and vault: `~/.hush/` (`HUSH_HOME` / `--home` in tests)
- Signal transport: `signal-cli` JSON receive/send, not a linked library
- Agent contract: `SKILL.md` — pull by name, never `signal-cli`, never vault files
- Validate with `cargo fmt`, `cargo test --locked`, `cargo clippy --locked -- -D warnings`
