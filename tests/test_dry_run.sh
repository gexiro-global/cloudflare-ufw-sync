#!/bin/bash
# Offline test: no network, no ufw changes. Verifies parsing, sanity bounds and dry-run.
# shellcheck disable=SC2015,SC2016,SC2181
# SC2015: the `[ cond ] && ok "..." || no "..."` shape is intentional here - `ok` cannot fail,
#         so this is a two-branch report, not a mis-written if-then-else.
# SC2016: single quotes are deliberate where a literal `$` belongs to awk, python or a stub.
# SC2181: these suites check `$?` immediately after the command under test, which is the
#         thing being asserted.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(CF_UFW_LOG=- "$HERE/../cf-ufw-sync.sh" --dry-run --source-file "$HERE/../examples/cloudflare-ips-v4.example.txt")
echo "$OUT"
echo "$OUT" | grep -q 'ranges=6'      || { echo 'FAIL: expected 6 parsed ranges'; exit 1; }
echo "$OUT" | grep -q 'DRY-RUN would-add' || { echo 'FAIL: expected dry-run add lines'; exit 1; }
echo "$OUT" | grep -q 'dry_run=1'     || { echo 'FAIL: dry-run flag not reported'; exit 1; }

# sanity bound must reject a truncated list
TMP=$(mktemp); printf '198.51.100.0/24\n' > "$TMP"
if CF_UFW_LOG=- "$HERE/../cf-ufw-sync.sh" --dry-run --source-file "$TMP" >/dev/null 2>&1; then
  echo 'FAIL: truncated list was accepted'; rm -f "$TMP"; exit 1
fi
rm -f "$TMP"

# A rule that ufw refuses to install must not be counted as added, and must fail the run.
STUB=$(mktemp -d)
printf '#!/bin/bash\ncase "$1" in status) exit 0;; *) exit 1;; esac\n' > "$STUB/ufw"
chmod +x "$STUB/ufw"
set +e
OUT=$(PATH="$STUB:$PATH" CF_UFW_LOG=- "$HERE/../cf-ufw-sync.sh" \
        --source-file "$HERE/../examples/cloudflare-ips-v4.example.txt" 2>&1)
RC=$?
set -e
rm -rf "$STUB"
echo "$OUT" | grep -q 'ADD-FAIL'   || { echo 'FAIL: a failed ufw call was not logged as ADD-FAIL'; exit 1; }
echo "$OUT" | grep -q 'added=0'    || { echo 'FAIL: a failed rule was counted as added'; exit 1; }
[ "$RC" -eq 1 ]                    || { echo "FAIL: expected exit 1 on install failure, got $RC"; exit 1; }

# A response that is mostly unparseable must abort. Filtering junk out and then sanity-checking
# only the survivors lets a mangled fetch through whenever enough plausible lines remain.
TMP2=$(mktemp)
printf '198.51.100.0/24\n203.0.113.0/24\n192.0.2.0/24\n198.18.0.0/16\n233.252.0.0/24\n' > "$TMP2"
printf 'not-a-range\njunk\njunk2\njunk3\njunk4\njunk5\n' >> "$TMP2"
set +e
OUT=$(CF_UFW_LOG=- "$HERE/../cf-ufw-sync.sh" --dry-run --source-file "$TMP2" 2>&1)
RC=$?
set -e
rm -f "$TMP2"
[ "$RC" -eq 1 ] || { echo "FAIL: a mostly-unparseable list was accepted (rc=$RC)"; exit 1; }
echo "$OUT" | grep -q 'refusing to act on this list' \
  || { echo 'FAIL: no abort reason was logged'; exit 1; }

# Duplicates and comments are not junk. Counting them as unparseable both misreported the
# warning and could reject a perfectly valid list.
TMP3=$(mktemp)
printf '198.51.100.0/24\n198.51.100.0/24\n203.0.113.0/24\n' > "$TMP3"
printf '192.0.2.0/24\n198.18.0.0/16\n233.252.0.0/24\n# a comment\n' >> "$TMP3"
set +e
OUT=$(CF_UFW_LOG=- "$HERE/../cf-ufw-sync.sh" --dry-run --source-file "$TMP3" 2>&1)
RC=$?
set -e
rm -f "$TMP3"
[ "$RC" -eq 0 ] || { echo "FAIL: a list with duplicates and a comment was rejected (rc=$RC)"; exit 1; }
echo "$OUT" | grep -q 'ABORT' && { echo 'FAIL: duplicates were treated as junk'; exit 1; }
echo "$OUT" | grep -q 'ranges=5' || { echo 'FAIL: expected 5 unique ranges'; exit 1; }

# --- strict validation -------------------------------------------------------------
# Shape-only checking accepted impossible addresses and deferred rejection to ufw.
BAD=$(mktemp)
printf '999.999.999.999/999\n1.2.3.4/33\n1.2.3/24\n1.2.3.4.5/24\n256.0.0.0/8\n' > "$BAD"
set +e
OUT=$(CF_UFW_LOG=- "$HERE/../cf-ufw-sync.sh" --dry-run --source-file "$BAD" 2>&1)
RC=$?
set -e
rm -f "$BAD"
[ "$RC" -ne 0 ] || { echo 'FAIL: a list of impossible CIDRs was accepted'; exit 1; }
echo "$OUT" | grep -q 'range-count=0' \
  || { echo 'FAIL: invalid CIDRs were not all rejected'; exit 1; }

# Valid IPv6 must still be accepted, or --ipv6 would be useless.
V6=$(mktemp)
printf '2400:cb00::/32\n2606:4700::/32\n2803:f800::/32\n2405:b500::/32\n2405:8100::/32\n' > "$V6"
set +e
OUT=$(CF_UFW_LOG=- "$HERE/../cf-ufw-sync.sh" --dry-run --ipv6 --source-file "$V6" 2>&1)
RC=$?
set -e
rm -f "$V6"
[ "$RC" -eq 0 ] || { echo "FAIL: valid IPv6 ranges were rejected (rc=$RC)"; exit 1; }
echo "$OUT" | grep -q 'ranges=5' || { echo 'FAIL: expected 5 IPv6 ranges'; exit 1; }

# Ports are operator input and must be validated before they reach ufw.
set +e
CF_UFW_LOG=- "$HERE/../cf-ufw-sync.sh" --dry-run --ports 'abc' --source-file /dev/null >/dev/null 2>&1
RC_A=$?
CF_UFW_LOG=- "$HERE/../cf-ufw-sync.sh" --dry-run --ports '70000' --source-file /dev/null >/dev/null 2>&1
RC_B=$?
set -e
[ "$RC_A" -eq 2 ] || { echo "FAIL: a non-numeric port was accepted (rc=$RC_A)"; exit 1; }
[ "$RC_B" -eq 2 ] || { echo "FAIL: an out-of-range port was accepted (rc=$RC_B)"; exit 1; }

# --- fail closed -------------------------------------------------------------------
# A log that cannot be written must stop the run before any firewall rule changes.
STUB=$(mktemp -d)
printf '%s\n' '#!/bin/bash' 'exit 0' > "$STUB/ufw"
printf '%s\n' '#!/bin/bash' 'exit 0' > "$STUB/flock"
chmod +x "$STUB/ufw" "$STUB/flock"
set +e
OUT=$(PATH="$STUB:$PATH" CF_UFW_LOG=/dev/null/cannot.log CF_UFW_LOCK="$STUB/lk" \
      "$HERE/../cf-ufw-sync.sh" --source-file "$HERE/../examples/cloudflare-ips-v4.example.txt" 2>&1)
RC=$?
set -e
rm -rf "$STUB"
[ "$RC" -eq 1 ] || { echo "FAIL: ran with an unwritable log (rc=$RC)"; exit 1; }
echo "$OUT" | grep -q 'refusing to change firewall rules' \
  || { echo 'FAIL: no reason given for refusing'; exit 1; }

echo 'PASS'
