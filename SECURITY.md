# Security & responsible use

Argus is a tool for **authorized** security testing only.

## Acceptable use

Only scan systems you own or are explicitly, in writing, permitted to test
(a signed engagement, a bug-bounty program whose scope includes the target, or
your own lab). Unauthorized scanning may be illegal in your jurisdiction.

Argus enforces this with two hard gates that cannot be bypassed from config
alone:

1. **Authorization affirmation** — a scan refuses to start unless you pass
   `--i-am-authorized` (or set `scope.authorized: true` / `ARGUS_AUTHORIZED=1`).
2. **Scope allowlist** — every request is checked against an explicit host
   allowlist. Private, loopback and link-local addresses are blocked unless you
   opt in with `--allow-private`.

The built-in checks are **non-destructive detection probes** (they identify
likely issues; they do not exploit, extract data, or modify state).

## Reporting a vulnerability in Argus itself

Please open a private security advisory on the repository rather than a public
issue. Include reproduction steps and affected versions.
