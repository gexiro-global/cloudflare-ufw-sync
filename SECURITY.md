# Security Policy

## Supported Versions

`cf-ufw-sync` v0.x is maintained on the latest v0.x release line.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting if it is enabled on this repository. Otherwise email
`admin@gexiro.com`.

Please include:

- A concise description of the issue.
- A minimal reproduction using `--source-file` and a synthetic range list.
- Your OS, `bash --version`, and `ufw --version`.

Do not include real firewall configurations, server addresses, or any other sensitive values in a report.

## Threat model

This script trusts the range list it fetches over TLS from Cloudflare. A successful attacker-in-the-middle
with a valid certificate for that host could cause additional ranges to be allowed on the configured
ports. The sanity bounds limit the blast radius but do not eliminate it. The script cannot be used to
remove existing rules, which bounds the worst case to over-permissive allow rules rather than loss of
access.

The script must run as root to modify UFW. Review it before granting that.
