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
# Exit codes: 0 ok | 1 fetch/sanity failure, or a rule failed to install | 2 usage error
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

for _p in $PORTS; do
  case "$_p" in
    ''|*[!0-9]*) echo "invalid port: '$_p'" >&2; exit 2 ;;
  esac
  if [ "$_p" -lt 1 ] || [ "$_p" -gt 65535 ]; then
    echo "port out of range: $_p" >&2; exit 2
  fi
done

TS=$(date -u +%FT%TZ)
log(){ if [ "$LOG" = "-" ]; then echo "$TS $*"; else echo "$TS $*" >> "$LOG"; fi; }

# Two cron runs overlapping would race each other into duplicate `ufw allow` calls and
# interleave the log. This fails CLOSED: if the lock cannot be taken - no flock available, no
# permission on the lock file - the run stops rather than proceeding unserialised. A firewall
# tool that quietly drops its own safety property is worse than one that refuses to start.
LOCK="${CF_UFW_LOCK:-/tmp/cf-ufw-sync.lock}"
if [ "$DRY" = "0" ]; then
  command -v flock >/dev/null 2>&1 \
    || { log "ABORT flock is not available; refusing to run without serialisation"
         echo "flock is required so two runs cannot modify the firewall at once" >&2
         exit 1; }
  if ! { exec 9>"$LOCK"; } 2>/dev/null; then
    log "ABORT cannot open lock file $LOCK"
    echo "cannot open lock file $LOCK - refusing to run unserialised" >&2
    exit 1
  fi
  flock -n 9 || { log "SKIP another run holds $LOCK"; exit 0; }
fi

# The log is the only record of what was changed. If it cannot be written, stop before
# touching any rule rather than making undocumented firewall changes.
if [ "$DRY" = "0" ] && [ "$LOG" != "-" ]; then
  if ! { : >> "$LOG"; } 2>/dev/null; then
    echo "cannot write to $LOG - refusing to change firewall rules unrecorded" >&2
    exit 1
  fi
fi

# Validate with the standard library rather than a hand-rolled parser. The previous version
# accepted 1::2::3/64 and 1:2:3:4:5:6:7:8:9/64 - IPv6 has more ways to be malformed than a
# regex comfortably covers, and getting it wrong means handing nonsense to the firewall.
is_cidr(){
  CIDR_CANDIDATE="$1" python3 -c '
import ipaddress, os, sys
try:
    ipaddress.ip_network(os.environ["CIDR_CANDIDATE"], strict=False)
except Exception:
    sys.exit(1)
' 2>/dev/null
}

fetch(){
  if [ -n "$SRC_FILE" ]; then cat "$SRC_FILE"; return; fi
  curl -fsS --max-time 20 "$V4_URL" || return 1
  if [ "$WANT_V6" = "1" ]; then echo; curl -fsS --max-time 20 "$V6_URL" || return 1; fi
}

RAW=$(fetch) || { log "FETCH-FAIL"; exit 1; }
# Count the lines that actually failed to parse, rather than subtracting the de-duplicated
# total from the raw line count - duplicates and comments are not junk, and counting them as
# junk both misreports the warning and can reject a perfectly good list.
DROPPED=$(printf '%s\n' "$RAW" \
  | grep -v '^[[:space:]]*$' | grep -v '^[[:space:]]*#' \
  | while IFS= read -r _l; do
      _l=${_l%%$'\r'}
      is_cidr "$_l" || printf 'x\n'
    done | grep -c .)
# Filter through is_cidr itself so "parsed" and "valid" cannot drift apart.
RANGES=$(printf '%s\n' "$RAW" | while IFS= read -r _l; do
  _l=${_l%%$'\r'}
  is_cidr "$_l" && printf '%s\n' "$_l"
done | sort -u)
CNT=$(printf '%s\n' "$RANGES" | grep -c . )

if [ "$CNT" -lt "$MIN_RANGES" ] || [ "$CNT" -gt "$MAX_RANGES" ]; then
  log "ABORT implausible-range-count=$CNT (expected ${MIN_RANGES}..${MAX_RANGES})"
  exit 1
fi

# Discarding unparseable lines and then sanity-checking only the survivors means a mangled
# response can still pass, as long as enough plausible-looking lines remain. If the fetch was
# mostly junk, treat the whole list as untrustworthy and change nothing.
if [ "$DROPPED" -gt 0 ]; then
  log "WARN dropped $DROPPED unparseable line(s) from the fetched list"
  if [ "$DROPPED" -ge "$CNT" ]; then
    log "ABORT more unparseable lines ($DROPPED) than valid ranges ($CNT) - refusing to act on this list"
    exit 1
  fi
fi

# --- pass 1: add anything missing -------------------------------------------
ADDED=0
ADD_FAILED=0
while IFS= read -r cidr; do
  is_cidr "$cidr" || continue
  for p in $PORTS; do
    if ufw status 2>/dev/null | grep -F "$cidr" | grep -qw "$p"; then continue; fi
    if [ "$DRY" = "1" ]; then
      log "DRY-RUN would-add $cidr port $p"
      ADDED=$((ADDED+1))
    elif ufw allow from "$cidr" to any port "$p" proto tcp comment cf-sync >/dev/null 2>&1; then
      log "ADDED $cidr port $p"
      ADDED=$((ADDED+1))
    else
      # A rule that failed to install is not an addition. Counting it would report success
      # for a firewall that was never actually changed.
      log "ADD-FAIL $cidr port $p"
      ADD_FAILED=$((ADD_FAILED+1))
    fi
  done
done <<< "$RANGES"

# --- pass 2: report ranges we allow that Cloudflare no longer publishes ------
FIRST_PORT=${PORTS%% *}
# Only consider rules this script created. Reporting hand-made allow rules as "stale Cloudflare
# ranges" sends the operator to review something that was never ours to manage.
IPT_RAW=$(iptables -S ufw-user-input 2>/dev/null)
IPT_RC=$?
CURRENT=$(printf '%s\n' "$IPT_RAW" \
  | grep "dport $FIRST_PORT" | grep -i 'cf-sync' | grep -oE '[0-9.]+/[0-9]+' | sort -u)
# No fallback to untagged rules. Reporting a hand-made allow rule as a retired Cloudflare
# range sends the operator to review something this tool never managed.
#
# And a firewall query that failed is not the same as one that found nothing: saying "stale=0"
# after iptables errored claims a check that never happened.
STALE_UNKNOWN=0
if [ "$IPT_RC" -ne 0 ]; then
  log "STALE-CHECK-UNKNOWN iptables exited $IPT_RC; existing rules could not be read"
  STALE_UNKNOWN=1
elif [ -z "$CURRENT" ]; then
  log "NOTE no cf-sync-tagged rules found; nothing to check for staleness"
fi
if [ "$WANT_V6" = "1" ]; then
  # iptables only knows IPv4; the v6 rules live in ip6tables, and omitting them would mean
  # retired Cloudflare IPv6 ranges are never reported as stale.
  IP6_RAW=$(ip6tables -S ufw6-user-input 2>/dev/null)
  IP6_RC=$?
  if [ "$IP6_RC" -ne 0 ]; then
    log "STALE-CHECK-UNKNOWN ip6tables exited $IP6_RC; v6 rules could not be read"
    STALE_UNKNOWN=1
  else
    CURRENT=$(printf '%s\n%s\n' "$CURRENT" "$(printf '%s\n' "$IP6_RAW" \
      | grep "dport $FIRST_PORT" | grep -i 'cf-sync' | grep -oiE '[0-9a-f:]+/[0-9]+' | sort -u)")
  fi
fi
STALE=0
while IFS= read -r have; do
  [ -z "$have" ] && continue
  printf '%s\n' "$RANGES" | grep -qxF "$have" || { log "STALE-ALERT $have review-manually"; STALE=$((STALE+1)); }
done <<< "$CURRENT"

if [ "$STALE_UNKNOWN" = 1 ]; then
  STALE_REPORT=unknown
else
  STALE_REPORT=$STALE
fi
log "OK ranges=$CNT added=$ADDED add_failed=$ADD_FAILED stale=$STALE_REPORT dry_run=$DRY"
[ "$ADD_FAILED" -eq 0 ] || exit 1
exit 0
