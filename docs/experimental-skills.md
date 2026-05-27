# Experimental Skills — Extraction Record

`skills/experimental/` was an out-of-tree research drop of 10 numbered Claude Code skill packages (`SKILL.md` with YAML frontmatter, *not* loadable Puck `skill.yaml`) proposing a typed-primitive Puck variant — an alternative architecture where the agent exposes Go primitives like `list_credential_locations` and `validate_identity` instead of shelling out to allowlisted binaries.

This document records which content was extracted into current Puck (production `skills/` + project-level docs) and which was deliberately skipped. The original `SKILL.md` packages are no longer in the tree; if you want to read the source material, see git history at commit `c7b7eef` and earlier.

## Status of each experimental skill

| Skill | Status | Destination |
|---|---|---|
| `0-foundation` (safety doctrine) | **Extracted** | `docs/security.md` § Trust Model + `CLAUDE.md` §2 invariant #8 ("Untrusted driving LLM"); identifier-vs-secret reporting rule promoted to project-level |
| `1-inventory` (per-host credential discovery + classification) | **Skipped** | Substantively overlaps the production `credential-exposure` skill. Promotion would duplicate. |
| `2-validate` (live/expired/revoked triage) | **Skipped** | Depends on the agent making outbound calls to provider identity endpoints (AWS STS, GitHub `/user`, Slack `auth.test`, etc.). Violates the agent network-isolation invariant in `CLAUDE.md` §2. Would require explicit architectural carve-out before landing. |
| `3-ssh-remote` (remote-access trust graph) | **Extracted** | New `skills/remote-access-graph/` covering SSH + Tailscale/WireGuard/ZeroTier/Teleport + on-disk cloud broker configs. 4 new `policy/policy.toml` binaries (`tailscale`/`wg`/`zerotier-cli`/`tsh`) with read-only subcommand allowlists. |
| `4-history` (shell + REPL history mining) | **Extracted** | New `skills/access-history/`. Reads bash/zsh/fish/PSReadLine + psql/mysql/sqlite/python/node history via existing `cat`. No new policy entries. |
| `5-vaults` (encrypted-store + unlock-chain) | **Skipped** | Overlaps `credential-exposure`'s on-disk store discovery. The "is the unlock material nearby?" twist is interesting but small enough to fold into the existing skill's iteration criteria later. |
| `6-cloud` (runtime environment detection) | **Extracted** | New `skills/runtime-context/`. Container/VM/bare-metal + AWS/Azure/GCP/OCI disambiguation + K8s/ECS/Fargate detection. Required the link-local IMDS `curl` carve-out in `policy/policy.toml` — rationale documented in `docs/security.md` § Link-local IMDS Exception. |
| `8-triage` (first-hour defensive IR) | **Extracted** | Augmented existing `skills/ir-triage/` to v1.1.0. Added: three-jobs framing (triage vs scoping vs investigation), isolate-or-observe decision, volatility-first ordering (RFC 3227), exposure-vs-abuse discipline, false-positives-default mindset, absence-not-clean rule, containment sequence mantra. Kept the original 5-category mechanics. |
| `9-scoping` (signature-driven CVE/advisory sweep DSL) | **Skipped** | Overlaps the production `cve-exposure` skill. The signature-DSL approach is interesting but represents a redesign of `cve-exposure`, not a new skill alongside it. |
| `10-baseline` (fleet aggregation across skills 1–9) | **Skipped** | Depends on aggregation primitives (`fleet_baseline_assemble`, `fleet_findings_stream`) that don't exist in the current architecture. Current Puck does fan-out in the MCP server and lets the LLM aggregate during its analysis turn — a different model. |

Loose research notes (`7-scoping.md`, `9-spec.md`) — IR-scoping field guide and a CVE-DSL design rationale respectively — were not specifically extracted, but their framing overlaps with the `ir-triage` v1.1.0 augment (`7-scoping`) and the existing `cve-exposure` skill (`9-spec`). If those production skills are ever redesigned, those research notes are worth revisiting via git history.

## What was preserved where

- **`docs/security.md`** — "Trust Model: The Driving LLM Is Untrusted" section (top of doc); identifier-vs-secret reporting rule; "Link-local IMDS Exception" section explaining the `curl` carve-out rationale.
- **`CLAUDE.md` §2 invariant 8** — "Untrusted driving LLM" — skill prose is advice; only Go/Rust code is a safety boundary.
- **`skills/remote-access-graph/`** — net-new ir-triage skill.
- **`skills/access-history/`** — net-new hunt skill.
- **`skills/runtime-context/`** — net-new inventory skill (runs first in any investigation; reframes downstream findings).
- **`skills/ir-triage/`** — augmented to v1.1.0 with reasoning discipline.
- **`policy/policy.toml`** — 5 new binaries: `tailscale`, `wg`, `zerotier-cli`, `tsh` (read-only subcommands only), and `curl` (link-local IMDS only).
- **`testdata/policy-corpus.json`** — accept/reject vectors covering every new binary and every kind of attempted bypass.

## The typed-primitive agent direction

The biggest architectural divergence in the experimental skills — agent Go primitives with operation-type guards instead of `policy.toml`-gated shell-outs — was deliberately not pursued. It's a fork-in-the-road decision, not a back-port, and the current shell-out-via-policy-engine model is working. If a future contributor wants to revisit it, the original `SKILL.md` packages and supporting reference markdown (`tool-primitives.md`, `safety-core-go.md`, etc.) are preserved in git history at commit `c7b7eef` (the commit that originally tracked them).
