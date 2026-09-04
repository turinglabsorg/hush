#!/usr/bin/env sh
set -eu

REPO="${HUSH_REPO:-turinglabsorg/hush}"
VERSION="${HUSH_VERSION:-latest}"
INSTALL_DIR="${HUSH_INSTALL_DIR:-$HOME/.local/bin}"
SOURCE="${HUSH_INSTALL_SOURCE:-}"
FROM_SOURCE=0
DRY_RUN=0
VERIFY_DOWNLOAD="${HUSH_INSTALL_VERIFY:-1}"
COSIGN_VERIFY="${HUSH_INSTALL_COSIGN:-auto}"
INSTALL_AGENT_SKILL=0
AGENT_SKILL_DIR="${HUSH_AGENT_SKILL_DIR:-$HOME/.agents/skills/hush}"
INSTALL_PATH_LINK=0
PATH_LINK_DIR="${HUSH_PATH_LINK_DIR:-/usr/local/bin}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || printf '.')

usage() {
  cat <<'USAGE'
Install hush from GitHub Releases.

Usage:
  ./install.sh [options]

Options:
  --version <tag>       Install a specific tag, for example v0.4.0.
  --install-dir <dir>   Install directory. Default: $HOME/.local/bin.
  --source <path|url>   Install from a local file or direct URL.
  --from-source         Build with cargo from this checkout.
  --agent-skill [dir]   Install the agent skill. Default: $HOME/.agents/skills/hush.
  --path-link [dir]     Symlink hush into a PATH directory. Default: /usr/local/bin.
  --no-verify           Skip SHA-256 verification for downloaded binaries.
  --cosign              Require cosign signature verification.
  --no-cosign           Skip optional cosign verification.
  --dry-run             Print actions without writing files.
  -h, --help            Show this help.
USAGE
}

fail() {
  printf 'hush install: %s\n' "$1" >&2
  exit 1
}

need_arg() {
  [ "$#" -gt 1 ] || fail "$1 requires a value"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --from-source)
      FROM_SOURCE=1
      shift
      ;;
    --version)
      need_arg "$@"
      VERSION="$2"
      shift 2
      ;;
    --install-dir)
      need_arg "$@"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --source)
      need_arg "$@"
      SOURCE="$2"
      shift 2
      ;;
    --agent-skill)
      INSTALL_AGENT_SKILL=1
      if [ "$#" -gt 1 ] && [ "${2#-}" = "$2" ]; then
        AGENT_SKILL_DIR="$2"
        shift 2
      else
        shift
      fi
      ;;
    --path-link)
      INSTALL_PATH_LINK=1
      if [ "$#" -gt 1 ] && [ "${2#-}" = "$2" ]; then
        PATH_LINK_DIR="$2"
        shift 2
      else
        shift
      fi
      ;;
    --no-verify)
      VERIFY_DOWNLOAD=0
      shift
      ;;
    --cosign)
      COSIGN_VERIFY=1
      shift
      ;;
    --no-cosign)
      COSIGN_VERIFY=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

detect_asset() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os:$arch" in
    Linux:x86_64|Linux:amd64) printf 'hush-linux-x86_64' ;;
    Darwin:x86_64|Darwin:amd64) printf 'hush-macos-x86_64' ;;
    Darwin:arm64|Darwin:aarch64) printf 'hush-macos-aarch64' ;;
    *) fail "unsupported platform: $os $arch" ;;
  esac
}

is_url() {
  case "$1" in
    http://*|https://*) return 0 ;;
    *) return 1 ;;
  esac
}

download() {
  source="$1"
  destination="$2"
  case "$source" in
    http://*|https://*)
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$source" -o "$destination"
      elif command -v wget >/dev/null 2>&1; then
        wget -qO "$destination" "$source"
      else
        fail "curl or wget is required to download $source"
      fi
      ;;
    *)
      [ -f "$source" ] || fail "source file does not exist: $source"
      cp "$source" "$destination"
      ;;
  esac
}

sha256_of_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required to verify downloads"
  fi
}

verify_sha256() {
  binary="$1"
  source_url="$2"
  checksum_file="$3"
  expected="$(awk 'NF {print $1; exit}' "$checksum_file")"
  [ -n "$expected" ] || fail "checksum file is empty: $source_url.sha256"
  actual="$(sha256_of_file "$binary")"
  if [ "$actual" != "$expected" ]; then
    fail "checksum mismatch for $source_url"
  fi
  printf 'verified sha256: %s\n' "$expected"
}

verify_cosign_blob() {
  binary="$1"
  source_url="$2"
  sig_file="$3"
  cert_file="$4"
  command -v cosign >/dev/null 2>&1 || fail "cosign is required by --cosign"
  identity_regexp="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v.*"
  cosign verify-blob \
    --certificate "$cert_file" \
    --signature "$sig_file" \
    --certificate-identity-regexp "$identity_regexp" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$binary" >/dev/null
  printf 'verified cosign signature: %s\n' "$source_url"
}

verify_downloaded_binary() {
  binary="$1"
  source_url="$2"
  [ "$VERIFY_DOWNLOAD" = "0" ] && return
  if ! is_url "$source_url"; then
    printf 'verification skipped: local source\n'
    return
  fi
  checksum_file="$(mktemp "${TMPDIR:-/tmp}/hush.sha256.XXXXXX")"
  download "$source_url.sha256" "$checksum_file"
  verify_sha256 "$binary" "$source_url" "$checksum_file"
  rm -f "$checksum_file"

  if [ "$COSIGN_VERIFY" = "0" ]; then
    return
  fi
  if [ "$COSIGN_VERIFY" = "auto" ] && ! command -v cosign >/dev/null 2>&1; then
    printf 'cosign verification skipped: cosign not found\n'
    return
  fi
  sig_file="$(mktemp "${TMPDIR:-/tmp}/hush.sig.XXXXXX")"
  cert_file="$(mktemp "${TMPDIR:-/tmp}/hush.pem.XXXXXX")"
  download "$source_url.sig" "$sig_file"
  download "$source_url.pem" "$cert_file"
  verify_cosign_blob "$binary" "$source_url" "$sig_file" "$cert_file"
  rm -f "$sig_file" "$cert_file"
}

raw_ref() {
  if [ "$VERSION" = "latest" ]; then
    printf 'main'
  else
    printf '%s' "$VERSION"
  fi
}

in_checkout() {
  [ -f "$SCRIPT_DIR/SKILL.md" ] && [ -f "$SCRIPT_DIR/Cargo.toml" ]
}

install_skill_file() {
  source_path="$1"
  destination="$2"
  if in_checkout && [ -f "$SCRIPT_DIR/$source_path" ]; then
    cp "$SCRIPT_DIR/$source_path" "$destination"
  else
    download "https://raw.githubusercontent.com/$REPO/$(raw_ref)/$source_path" "$destination"
  fi
}

install_agent_skill() {
  skill_dir="$1"
  printf 'agent skill: %s\n' "$skill_dir"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'dry-run: would install agent skill files\n'
    return
  fi
  mkdir -p "$skill_dir"
  install_skill_file "SKILL.md" "$skill_dir/SKILL.md"
  install_skill_file "README.md" "$skill_dir/README.md"
  printf 'agent skill installed: %s\n' "$skill_dir"
}

build_from_source() {
  in_checkout || fail "--from-source requires a hush git checkout"
  command -v cargo >/dev/null 2>&1 || fail "cargo is required for --from-source"
  printf 'building hush from %s\n' "$SCRIPT_DIR"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'dry-run: would cargo build --release --locked\n'
    printf '%s\n' "$SCRIPT_DIR/target/release/hush"
    return
  fi
  cargo build --release --locked --manifest-path "$SCRIPT_DIR/Cargo.toml"
  printf '%s\n' "$SCRIPT_DIR/target/release/hush"
}

if [ "$FROM_SOURCE" -eq 1 ]; then
  SOURCE="$(build_from_source)"
elif [ -z "$SOURCE" ]; then
  asset="$(detect_asset)"
  if [ "$VERSION" = "latest" ]; then
    SOURCE="https://github.com/$REPO/releases/latest/download/$asset"
  else
    SOURCE="https://github.com/$REPO/releases/download/$VERSION/$asset"
  fi
fi

target="$INSTALL_DIR/hush"

printf 'hush install\n'
printf 'source: %s\n' "$SOURCE"
printf 'target: %s\n' "$target"

if [ "$DRY_RUN" -eq 0 ]; then
  mkdir -p "$INSTALL_DIR"
  if [ "$FROM_SOURCE" -eq 1 ]; then
    cp "$SOURCE" "$target"
  else
    tmp="$(mktemp "${TMPDIR:-/tmp}/hush.XXXXXX")"
    trap 'rm -f "$tmp"' EXIT INT TERM
    download "$SOURCE" "$tmp"
    verify_downloaded_binary "$tmp" "$SOURCE"
    mv "$tmp" "$target"
  fi
  chmod +x "$target"
  "$target" --help >/dev/null
  printf 'installed: %s\n' "$target"
else
  printf 'dry-run: no files written\n'
fi

if [ "$INSTALL_AGENT_SKILL" -eq 1 ]; then
  printf '\n'
  install_agent_skill "$AGENT_SKILL_DIR"
fi

if [ "$INSTALL_PATH_LINK" -eq 1 ]; then
  printf '\n'
  printf 'path link: %s -> %s\n' "$PATH_LINK_DIR/hush" "$target"
  if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$PATH_LINK_DIR"
    ln -sf "$target" "$PATH_LINK_DIR/hush"
  fi
fi
