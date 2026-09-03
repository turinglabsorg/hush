# Hush

Rust CLI + agent skill. Secrets are ingested from Bitwarden (`hush pull` from a Send URL or vault item, `hush listen` polls for `hush put NAME` items), stored with age, and used with `hush run --name`. The binary must not print plaintext.

- Config and vault: `~/.hush/` (`HUSH_HOME` / `--home` in tests)
- Bitwarden transport: `bw` CLI as an external process (Send `receive` + vault `get`/`list`), never linked; auth via `BW_SESSION`/`BITWARDENCLI_APPDATA_DIR`, binary override `HUSH_BW_BIN`
- Agent contract: `SKILL.md` — pull by name, never `bw get`/`bw send receive` by hand, never vault files; Send passwords only via `--passwordenv`/`--passwordfile`; email-gated Sends via `--email` + `--code-cmd`/`--codeenv`/`--codefile` (codes single-use, newest wins)
- Tests stub `bw` with `tests/fixtures/fake-bw.sh`
- Validate with `cargo fmt`, `cargo test --locked`, `cargo clippy --locked -- -D warnings`
- GitHub Releases are built by `.github/workflows/release.yml` on `v*` tags (linux-x86_64, macos-x86_64, macos-aarch64, sha256 + cosign)
