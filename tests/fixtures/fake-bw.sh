#!/usr/bin/env bash
# Fake `bw` (Bitwarden CLI) for hush integration tests.
# Backed by $FAKE_BW_DIR:
#   state                 unlocked|locked|loggedout (default: unlocked)
#   items/<id>.json       {"id","name","login":{"password"},"notes"}
#   sends/<id>.name       send name (informational)
#   sends/<id>.txt        send text content
#   sends/<id>.password   if present, the required send password
set -eu

DIR="${FAKE_BW_DIR:-}"
[ -n "$DIR" ] || { echo "FAKE_BW_DIR is not set" >&2; exit 1; }

state="unlocked"
[ -f "$DIR/state" ] && state="$(cat "$DIR/state")"

fail() { echo "$1" >&2; exit 1; }

cmd="${1:-}"
shift || true

case "$cmd" in
  status)
    echo "{\"serverUrl\":\"https://vault.bitwarden.com\",\"lastSync\":\"2026-01-01T00:00:00Z\",\"userEmail\":\"agent@example.com\",\"userId\":\"fake\",\"status\":\"$state\"}"
    ;;
  sync)
    [ "$state" = "loggedout" ] && fail "Not logged in."
    [ "$state" = "locked" ] && fail "Vault is locked."
    echo "Syncing complete."
    ;;
  list)
    kind="${1:-}"; shift || true
    [ "$kind" = "items" ] || fail "unsupported list $kind"
    search=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --search) search="${2:-}"; shift 2 ;;
        *) shift ;;
      esac
    done
    out="["
    first=1
    for f in "$DIR"/items/*.json; do
      [ -f "$f" ] || continue
      if [ -n "$search" ]; then
        grep -qi "$search" "$f" || continue
      fi
      [ "$first" -eq 1 ] || out="$out,"
      out="$out$(cat "$f")"
      first=0
    done
    echo "$out]"
    ;;
  get)
    kind="${1:-}"; shift || true
    [ "$kind" = "item" ] || fail "unsupported get $kind"
    query="${1:-}"
    # exact id first
    if [ -f "$DIR/items/$query.json" ]; then cat "$DIR/items/$query.json"; exit 0; fi
    for f in "$DIR"/items/*.json; do
      [ -f "$f" ] || continue
      grep -qi "$query" "$f" && { cat "$f"; exit 0; }
    done
    fail "Not found."
    ;;
  delete)
    kind="${1:-}"; shift || true
    [ "$kind" = "item" ] || fail "unsupported delete $kind"
    id="${1:-}"
    [ -f "$DIR/items/$id.json" ] || fail "Not found."
    rm "$DIR/items/$id.json"
    ;;
  send)
    sub="${1:-}"; shift || true
    case "$sub" in
      receive)
        url="${1:-}"; shift || true
        id="$(basename "$url")"
        [ -f "$DIR/sends/$id.txt" ] || fail "Send not found."
        if [ -f "$DIR/sends/$id.password" ]; then
          expected="$(cat "$DIR/sends/$id.password")"
          given=""
          while [ "$#" -gt 0 ]; do
            case "$1" in
              --password) given="${2:-}"; shift 2 ;;
              --passwordenv) var="${2:-}"; given="${!var:-}"; shift 2 ;;
              --passwordfile) given="$(head -n 1 "${2:-/dev/null}")"; shift 2 ;;
              *) shift ;;
            esac
          done
          [ "$given" = "$expected" ] || fail "Invalid password."
        fi
        cat "$DIR/sends/$id.txt"
        ;;
      *) fail "unsupported send $sub" ;;
    esac
    ;;
  *) fail "unsupported command $cmd" ;;
esac
