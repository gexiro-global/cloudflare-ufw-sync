# cf-ufw-sync

[![CI](https://github.com/gexiro-global/cloudflare-ufw-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/gexiro-global/cloudflare-ufw-sync/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![ShellCheck](https://img.shields.io/badge/shellcheck-clean-brightgreen.svg)](.github/workflows/ci.yml)

Keep a UFW allowlist in sync with Cloudflare's published IP ranges — without ever locking yourself out.

If your origin sits behind Cloudflare, you probably want ports 80/443 reachable only from Cloudflare's
ranges. Those ranges change. Most published recipes solve this by flushing the firewall and rebuilding
it from a freshly fetched list. That works right up until the fetch returns a truncated file, a captive
portal page, or nothing at all — and then the rebuild removes the rules that were keeping your own
traffic alive.

`cf-ufw-sync` takes the opposite position.

## Design rules

**1. Additive only.** The script never deletes a UFW rule. Ranges you allow that Cloudflare no longer
publishes are written to the log as `STALE-ALERT` for a human to review. An extra allow is a small
problem; a removed allow can be an outage.

**2. Refuse implausible input.** Cloudflare publishes roughly 15 IPv4 and 7 IPv6 ranges. If the fetched
list parses to fewer than 5 or more than 60 entries, the script aborts and changes nothing. This is the
check that catches a truncated response before it becomes a firewall change.

**3. Dry run is first-class.** `--dry-run` prints every rule it would add and touches nothing, so you
can see the diff before it exists.

## Install

```bash
curl -fsSLO https://raw.githubusercontent.com/gexiro-global/cloudflare-ufw-sync/main/cf-ufw-sync.sh
chmod +x cf-ufw-sync.sh
sudo mv cf-ufw-sync.sh /usr/local/bin/cf-ufw-sync
```

Requires `bash`, `curl`, `ufw`, and `iptables` (used read-only, for the stale check).

## Usage

```bash
cf-ufw-sync --dry-run                 # show what would change
sudo cf-ufw-sync                      # sync IPv4 on ports 80 and 443
sudo cf-ufw-sync --ipv6               # include IPv6 ranges
sudo cf-ufw-sync --ports "443"        # HTTPS only
```

Run it from cron once a day:

```cron
17 4 * * * /usr/local/bin/cf-ufw-sync
```

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `CF_UFW_LOG` | `/var/log/cf-ufw-sync.log` | Log destination. Use `-` for stdout. |
| `CF_UFW_PORTS` | `80 443` | Default port list. |

### Log lines

```
2026-01-01T04:17:00Z ADDED 198.51.100.0/24 port 443
2026-01-01T04:17:00Z STALE-ALERT 203.0.113.0/24 review-manually
2026-01-01T04:17:00Z OK ranges=15 added=1 stale=1 dry_run=0
```

Exit codes: `0` success, `1` fetch or sanity failure (nothing changed), `2` usage error.

## What this tool does NOT do

- It does not remove firewall rules, ever. Cleaning up stale ranges is a manual decision.
- It does not configure UFW's default policy. If your default inbound policy is `allow`, adding
  Cloudflare ranges achieves nothing — set `ufw default deny incoming` yourself, deliberately.
- It does not protect ports other than the ones you name.
- It does not verify that the traffic reaching you actually came through Cloudflare. IP allowlisting is
  one layer; consider Cloudflare Authenticated Origin Pulls for the rest.
- It is not a substitute for keeping your origin's real address out of public DNS history.

## Limitations you should read before running this as root

This script edits a firewall. Run `--dry-run` first. If you administer the machine over SSH on a port
covered by `--ports`, understand that adding restrictive allows to a `deny incoming` policy can cut your
own session. Keep an out-of-band console available the first time you run it.

## Testing

```bash
./tests/test_dry_run.sh
```

The test runs fully offline against a synthetic fixture in `examples/` — no network, no firewall access.

## License

Apache-2.0. See [LICENSE](LICENSE).

Built and maintained by Gexiro Global Enterprises Ltd.
