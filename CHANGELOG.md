# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - Unreleased

### Added
- Initial public release.
- Additive-only sync of Cloudflare IPv4 ranges into a UFW allowlist.
- `--ipv6` for Cloudflare IPv6 ranges.
- `--dry-run` that reports intended changes without touching the firewall.
- `--ports` and `CF_UFW_PORTS` for arbitrary port lists.
- `--source-file` for offline testing against a fixture.
- Sanity bounds on the parsed range count; aborts rather than acting on an implausible list.
- `STALE-ALERT` reporting for allowed ranges Cloudflare no longer publishes.
