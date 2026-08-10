## Summary

Describe the change and why it is needed.

## Verification

- [ ] `shellcheck cf-ufw-sync.sh tests/run_tests.sh tests/test_dry_run.sh` is clean
- [ ] `./tests/run_tests.sh` passes
- [ ] Any new fail-open path (a failure or skip reported as success) has a regression test

## Safety

This tool edits UFW rules as root.

- [ ] The change keeps it **additive-only** (it never deletes a rule) and fail-closed on
      any error (fetch/sanity failure, lock issue, unreadable firewall state).
- [ ] `--dry-run` still previews changes without touching the firewall.
- [ ] `Signed-off-by:` (DCO) present.
