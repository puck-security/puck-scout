# Contributing to Puck

## Before You Start

1. **Read `CLAUDE.md`** at the repo root. It describes the architectural invariants and conventions.
2. **Read the component-specific `CLAUDE.md`** for the area you're working in (`agent/CLAUDE.md`, `mcp/CLAUDE.md`, or `skills/CLAUDE.md`).
3. For architectural changes, raise an issue or discussion first to get alignment before opening a PR.

## Types of Contributions

### Skills (lowest barrier to entry)

The easiest way to contribute is a new investigation skill. Skills are YAML -- no Rust or Go required.

1. Create a new directory under `skills/` with your skill name (lowercase, hyphens)
2. Write a `skill.yaml` following the structure of existing skills (see `skills/blast-radius/skill.yaml` for a good example)
3. The skill should define: `guidance.objective`, `guidance.pathfinder_strategy`, `guidance.fleet_strategy`, `guidance.iteration_criteria`, and `guidance.analysis_template`
4. Write a `README.md` explaining when to use the skill and how to interpret results
5. Submit a PR with a real-world example investigation showing the skill working end-to-end

Example skill categories:
- `ir-triage`: Incident response triage and blast radius
- `hunt`: Threat hunting queries
- `compliance`: Configuration and patch compliance
- `inventory`: Asset and software inventory
- `red-team`: Red team artifact detection

### Bug Fixes

1. Open an issue describing the bug (or find an existing one)
2. Create a branch: `fix/description`
3. Write a test that reproduces the bug
4. Fix the bug
5. Verify the test passes
6. Submit a PR

### New Features

1. Open an issue or discussion describing the feature
2. For architectural changes, get alignment in the issue before opening a PR
3. Create a branch: `feat/description`
4. Implement with tests
5. Submit a PR

## Development Workflow

### Local end-to-end loop (`test/` harness)

The `test/` directory contains a make-driven harness for testing a source
build end to end on your own machine.  Two run targets, one decision:

- **`make test-install`** — builds both binaries, runs the install scripts
  against a sandboxed `test/out/` prefix, writes a `.mcp.json` at the repo
  root that points at the test binaries.  Safe to run from Claude Code's
  bash tool (writes only to current dir and `$TMPDIR`).
- **`make run-agent`** — starts only the agent.  Use this when Claude Code
  is also running and you want its stdio puck-mcp to own port 50281.
- **`make run`** — starts a standalone HTTP puck-mcp + agent.  Use this
  when Claude Code is **not** running.  Quit Claude Code first or it'll
  race the bind on 50281.

Both `make run` and `make run-agent` (and Claude Code's own stdio puck-mcp
forked from `.mcp.json`) want the agent mTLS listener on 50281, and only
one process can bind it.  `puck-mcp` exits fatally on the conflict — pick
one launcher per session.  Run `cd test && make` with no args for the full
decision tree.

> **Sandbox note.** Background processes started via Claude Code's bash
> tool are killed when the tool call exits — `make run` and `make run-agent`
> must be invoked from a real terminal outside Claude Code so they survive.

### Branch Naming

- `feat/` -- new features
- `fix/` -- bug fixes
- `chore/` -- maintenance, dependencies, tooling
- `docs/` -- documentation changes

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add list_processes command to endpoint agent
fix: handle timeout correctly in fan-out coordinator
docs: clarify mTLS enrollment in getting-started
chore: update tokio to 1.36
skill: add shadow-ai investigation skill
```

### Code Quality

**Rust (agent)**:
```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo audit
```

**Go (MCP server)**:
```bash
gofmt -l .
go vet ./...
go test ./...
staticcheck ./...
```

**Skills**:
- Follow the structure of existing skills (especially `blast-radius`)
- Include a README with usage context
- Test your skill by running an actual investigation with it

### Pull Requests

- All PRs require one human reviewer
- Fill out the PR template completely
- Include test results
- Keep PRs focused -- one logical change per PR

## What We Will Not Accept

- Changes that violate the read-only invariant
- Investigation logic implemented as Go code in the MCP server (skills are YAML)
- Web UI components (Puck is MCP-native; the UI is the MCP client)
- Telemetry or analytics code
- Dependencies without justification
- Changes without tests (for Rust and Go code)

## Extending the Policy Engine (Adding New Commands)

The single source of truth for command safety is `policy/policy.toml`, embedded at compile time into both `puck-agent` (Rust) and `puck-mcp` (Go). The same grammar is enforced by both binaries — a CI parity gate (`make test-policy-parity`) verifies they agree before any PR can merge.

### Adding a New Binary to the Policy

The shared policy at `policy/policy.toml` is embedded into both binaries at compile time. To add a new binary that an investigation skill needs:

1. Determine if it is truly read-only (does it modify files, kill processes, or open network connections? If any doubt, it does not belong here).

2. Edit `policy/policy.toml`. Add a `[binary.<name>]` block with:
   - `canonical_paths`: list of absolute paths where the binary lives on supported platforms.
   - `flags`: typed flag grammar (each flag declares a `value` kind: `none`, `string`, `glob`, `uint`, `duration`, `fs_path`, or `enum`).
   - `forbidden_flags`: explicit reject list as belt-and-suspenders.
   - `positional`: typed positional spec (or omit if the binary takes no positional args).
   - `subcommand_required` + `subcommands`: for binaries with structured subcommand grammars (aws, gh, kubectl).

3. Add at least one **accept** and one **reject** test vector to `testdata/policy-corpus.json`. The reject vector should target the most dangerous flag you're forbidding.

4. Open a PR. CI runs the corpus parity test against both the Rust and Go implementations — they must agree.

5. Document the addition in your PR description with a safety justification — explain why each allowed flag cannot be used for state modification.

The operator override file at `/etc/puck/policy-overrides.toml` can **enable, disable, or re-path** existing entries but cannot author new grammar — new binaries always require a repo PR.

Note: Removing entries from `policy.toml` has a higher review bar. The policy engine is the last line of defense.

## Contributor License Agreement

Before we can merge your contribution, you (or your employer) need to sign Puck's CLA.  It is adapted from the Apache Software Foundation's well-known Individual + Corporate CLA templates — the same shape used by Confluent, Linkerd, Vert.x, and hundreds of other commercial-OSS projects.  The CLA Assistant bot will comment on your first PR with a one-line sign-here prompt; no PDFs, no DocuSign.

- **Individual contributor** (your own time, no employer claim on the work): sign the [Individual CLA](../CLA.md#individual-contributor-license-agreement).
- **Contributing on behalf of your employer**: have a signatory authorised to bind the company sign the [Corporate CLA](../CLA.md#corporate-contributor-license-agreement), and list authorised employees in the PR comment.

The short version: you keep copyright in your contribution; Puck Security gets a perpetual licence to use, modify, sublicense, and distribute it as part of the project (including under future licences if the project ever relicenses).  You assert the work is your original creation.

Signatures are recorded in [`signatures/version1/cla.json`](../signatures/version1/cla.json) and tied to your GitHub username + the commit SHA signed against.  Sign once, contribute forever (until the CLA text materially changes — the bot will re-prompt if it does).

If you've already signed for another Puck repo under the same GitHub account, the bot will recognise that and skip the prompt.  If it doesn't, comment `recheck` and it will re-verify.

## Getting Help

Open an issue or discussion on GitHub. For security vulnerabilities, see [SECURITY.md](../SECURITY.md).
