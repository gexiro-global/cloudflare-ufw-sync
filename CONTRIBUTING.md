# Contributing

Thanks for considering a contribution.

This is a small, deliberately narrow tool. The most useful contributions are bug reports with a
reproduction, and patches that keep the script under one screen of logic.

## Ground rules

- **The additive-only rule is not negotiable.** Pull requests that add automatic rule deletion will be
  closed. If you want cleanup, build it as a separate opt-in script that prints commands for a human.
- Keep it POSIX-friendly `bash`, no runtime dependencies beyond `curl`, `ufw`, `iptables`.
- `shellcheck` must pass clean.
- New behaviour needs a case in `tests/test_dry_run.sh` that runs offline.

## Support expectations

This project is maintained on a best-effort basis. There is no SLA, no guaranteed response time, and no
commercial support attached to it. If it is load-bearing for you, vendor it.
