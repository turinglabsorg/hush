# Hush

Rust CLI + agent skill. Secrets are ingested from Bitwarden (`hush pull` from a Send URL or vault item, `hush listen` polls for `hush put NAME` items), stored with age, and used with `hush run --name`. The binary must not print plaintext.

- Config and vault: `~/.hush/` (`HUSH_HOME` / `--home` in tests)
- Bitwarden transport: `bw` CLI as an external process (Send `receive` + vault `get`/`list`), never linked; auth via `BW_SESSION`/`BITWARDENCLI_APPDATA_DIR`, binary override `HUSH_BW_BIN`
- Agent contract: `SKILL.md` — pull by name, never `bw get`/`bw send receive` by hand, never vault files; Send passwords only via `--passwordenv`/`--passwordfile`; email-gated Sends via `--email` + `--code-cmd`/`--codeenv`/`--codefile` (codes single-use, newest wins)
- Locally originated credentials use `hush generate NAME`; it must generate with the OS CSPRNG, encrypt immediately, refuse replacement without `--force`, and print metadata only.
- Agent-owned Bitwarden recovery stores the master password as `BITWARDEN_MASTER_PASSWORD` and runs `hush bitwarden unlock --email ADDRESS`; the command passes the password to `bw` only through an environment variable, discards authentication stderr, stores the fresh session as encrypted `BITWARDEN_SESSION`, and never prints either value. After a lock, rerun the same command and use the session only through `hush run --name BITWARDEN_SESSION --env BW_SESSION --redact -- ...`.
- `hush doctor` and `hush bitwarden status` must validate the encrypted `BITWARDEN_SESSION` themselves when no ambient `BW_SESSION` exists; status checks may inject the session only into the scoped `bw status` subprocess and must never print it.
- Tests stub `bw` with `tests/fixtures/fake-bw.sh`
- Validate with `cargo fmt`, `cargo test --locked`, `cargo clippy --locked -- -D warnings`
- GitHub Releases are built by `.github/workflows/release.yml` on `v*` tags (linux-x86_64, macos-x86_64, macos-aarch64, sha256 + cosign)
