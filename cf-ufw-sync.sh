#!/bin/bash
# cf-ufw-sync - keep a UFW allowlist in sync with Cloudflare's published IP ranges.
#
# Design rule: ADDITIVE ONLY. This script never deletes a UFW rule. Ranges that are
# no longer published by Cloudflare are reported as STALE-ALERT for manual review.
# Rationale: an automated delete pass that runs against a truncated or hijacked
# range list will lock you out of your own origin. Adding a stale allow is a much
# smaller problem than removing a live one.
#
# Usage:
#   cf-ufw-sync.sh [--dry-run] [--ipv6] [--ports "80 443"] [--source-file PATH]
#
# Environment:
#   CF_UFW_LOG    log destination (default: /var/log/cf-ufw-sync.log, "-" for stdout)
#   CF_UFW_PORTS  default port list when --ports is not given
#
# Exit codes: 0 ok | 1 fetch/sanity failure | 2 usage error
set -uo pipefail

LOG="${CF_UFW_LOG:-/var/log/cf-ufw-sync.log}"
PORTS="${CF_UFW_PORTS:-80 443}"
DRY=0
WANT_V6=0
SRC_FILE=""
V4_URL="https://www.cloudflare.com/ips-v4"
V6_URL="https://www.cloudflare.com/ips-v6"

# Sanity bounds. Cloudflare publishes ~15 IPv4 and ~7 IPv6 ranges. A list far
# outside these bounds means the fetch was truncated, redirected or tampered with.
MIN_RANGES=5
MAX_RANGES=60

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)     DRY=1 ;;
    --ipv6)        WANT_V6=1 ;;
    --ports)       shift; PORTS="${1:?--ports needs a value}" ;;
    --source-file) shift; SRC_FILE="${1:?--source-file needs a path}" ;;
    -h|--help)     sed -n '2,20p' "$0"; exit 0 ;;
    *)             echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

TS=$(date -u +%FT%TZ)
log(){ if [ "$LOG" = "-" ]; then echo "$TS $*"; else echo "$TS $*" >> "$LOG"; fi; }

is_cidr(){ printf '%s\n' "$1" | grep -qE '^[0-9a-fA-F:.]+/[0-9]{1,3}$'; }

fetch(){
  if [ -n "$SRC_FILE" ]; then cat "$SRC_FILE"; return; fi
  curl -fsS --max-time 20 "$V4_URL" || return 1
  if [ "$WANT_V6" = "1" ]; then echo; curl -fsS --max-time 20 "$V6_URL" || return 1; fi
}

RANGES=$(fetch) || { log "FETCH-FAIL"; exit 1; }
RANGES=$(printf '%s\n' "$RANGES" | grep -E '^[0-9a-fA-F:.]+/[0-9]{1,3}$' | sort -u)
CNT=$(printf '%s\n' "$RANGES" | grep -c . )

if [ "$CNT" -lt "$MIN_RANGES" ] || [ "$CNT" -gt "$MAX_RANGES" ]; then
  log "ABORT implausible-range-count=$CNT (expected ${MIN_RANGES}..${MAX_RANGES})"
  exit 1
fi

# --- pass 1: add anything missing -------------------------------------------
ADDED=0
while IFS= read -r cidr; do
  is_cidr "$cidr" || continue
  for p in $PORTS; do
    if ufw status 2>/dev/null | grep -F "$cidr" | grep -qw "$p"; then continue; fi
    if [ "$DRY" = "1" ]; then
      log "DRY-RUN would-add $cidr port $p"
    else
      ufw allow from "$cidr" to any port "$p" proto tcp comment cf-sync >/dev/null 2>&1 \
        && log "ADDED $cidr port $p" \
        || log "ADD-FAIL $cidr port $p"
    fi
    ADDED=$((ADDED+1))
  done
done <<< "$RANGES"

# --- pass 2: report ranges we allow that Cloudflare no longer publishes ------
FIRST_PORT=$(echo $PORTS | awk '{print $1}')
CURRENT=$(iptables -S ufw-user-input 2>/dev/null \
  | grep "dport $FIRST_PORT" | grep -oE '[0-9.]+/[0-9]+' | sort -u)
STALE=0
while IFS= read -r have; do
  [ -z "$have" ] && continue
  printf '%s\n' "$RANGES" | grep -qxF "$have" || { log "STALE-ALERT $have review-manually"; STALE=$((STALE+1)); }
done <<< "$CURRENT"

log "OK ranges=$CNT added=$ADDED stale=$STALE dry_run=$DRY"
exit 0
