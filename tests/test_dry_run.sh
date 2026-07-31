#!/bin/bash
# Offline test: no network, no ufw changes. Verifies parsing, sanity bounds and dry-run.
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

echo 'PASS'
