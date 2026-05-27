# Contributing to Puck

Thanks for your interest in Puck!  The full contribution guide lives at [docs/contributing.md](docs/contributing.md) — start there.

## TL;DR

1. **Read [CLAUDE.md](CLAUDE.md)** for the architectural invariants (read-only agent, audit-before-execute, skills as YAML, etc.).
2. **Sign the [CLA](CLA.md)** — the bot will prompt you with the one-line sign-here text on your first PR.
3. **Use conventional commits** (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, `test:`).
4. **One concern per PR.**  Small focused PRs review faster than large ones.
5. **Tests for new code.**  See the component-specific `CLAUDE.md` (agent/, mcp/, skills/) for the test bar in each area.

## Where to start

- **Easiest contribution**: a new investigation skill.  Skills are YAML — no Rust or Go required.  See [docs/contributing.md#skills-lowest-barrier-to-entry](docs/contributing.md#skills-lowest-barrier-to-entry).
- **Bug fixes**: open or pick up an issue, branch as `fix/short-name`.
- **New features**: open a discussion or issue first.  For architectural changes, get alignment in the issue before opening a PR.

## Code of conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Security issues

Do not file public issues for security vulnerabilities.  See [SECURITY.md](SECURITY.md).
