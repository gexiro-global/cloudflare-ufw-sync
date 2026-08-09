# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

- No unreleased changes.

## [0.1.0]

### Security
- Lock via a validated, owner-checked directory under `/run/lock` opened read-only
  (a directory cannot be truncated), replacing a predictable `/tmp` lock file opened
  with `>` that a local user could redirect at an arbitrary root-writable file (CWE-59).

### Fixed
- A failed `ufw status` now aborts instead of being treated as "rule absent" and
  falling through to `ufw allow`.
- Lock contention now exits `4` (distinct), and additions-applied-but-staleness-
  unverifiable now exits `5` and is not labelled `OK`, so schedulers can tell a
  completed sync from a skipped or partial one.

### Added
- Initial public release.
- Additive-only sync of Cloudflare IPv4 ranges into a UFW allowlist.
- `--ipv6` for Cloudflare IPv6 ranges.
- `--dry-run` that reports intended changes without touching the firewall.
- `--ports` and `CF_UFW_PORTS` for arbitrary port lists.
- `--source-file` for offline testing against a fixture.
- Sanity bounds on the parsed range count; aborts rather than acting on an implausible list.
- `STALE-ALERT` reporting for allowed ranges Cloudflare no longer publishes.
