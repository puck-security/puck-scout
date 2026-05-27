# runtime-context

Detect the host's runtime environment — container vs VM vs bare-metal, which cloud, which orchestrator, IMDS reachability — before any other investigation step.

## When to use

- Always — run this first on any host you've not investigated before.
- Specifically when an alert's interpretation depends on context: "process listening on 169.254.169.254" is benign on a cloud VM and suspicious on a laptop.
- Fleet baselining: "what's actually in our fleet — container vs VM, what clouds?"
- Before running `aws-blast-radius` or any cloud-specific skill, to confirm the relevant cloud and account context.

## Why it matters

Every other finding gets reframed by runtime context:

- Service-account JSON in `/var/run/secrets/` is normal in a Kubernetes pod, a high-severity exposure on bare metal.
- `aws sts get-caller-identity` returning a role means different things on an EC2 instance with an attached profile vs a developer laptop with hardcoded keys.
- A process bound to `169.254.169.254` is the IMDS endpoint reflection on a cloud VM; on a laptop, it's potential canary or honeytoken bait.

Running runtime-context first costs ~1-3 minutes and prevents misinterpretation across the rest of the investigation.

## How it works

Reachability and metadata probes only. Reads:

- `/proc/1/cgroup`, `/proc/self/mountinfo`, `/.dockerenv`, `/run/.containerenv` — container detection.
- `/sys/class/dmi/id/{sys_vendor,product_name,board_asset_tag}` — virtualization + cloud detection from BIOS/SMBIOS.
- `/var/run/secrets/kubernetes.io/serviceaccount/` — K8s pod detection.
- `/proc/1/environ`, `/proc/self/environ` — orchestrator env vars (ECS, Fargate, Lambda, Cloud Run, GCP Functions).
- Link-local IMDS at `http://169.254.169.254/` — disambiguates AWS / Azure / GCP / OCI by response shape. Sends benign metadata `GET`s (and IMDSv2 `PUT` for token endpoint); never reads from `/iam/security-credentials/<role>` (which would return a live IAM credential).

## What it deliberately does NOT do

- Fetch IAM credentials from the IMDS credentials endpoint.
- Enumerate cloud resources (list S3 buckets, list IAM users, etc.).
- Authenticate to anything.
- Read process memory.

The IMDS curl access is limited to `http://169.254.169.254/` via a positional URL prefix in `policy/policy.toml`. Any other URL — `https://example.com`, `http://attacker.example.com`, no-scheme `169.254.169.254/...`, GCP's alternative `metadata.google.internal` — is rejected. The accept/reject vectors are in `testdata/policy-corpus.json`.

## The link-local carve-out

This skill is the first place Puck's agent makes any HTTP call outside its configured MCP server. The decision rationale is documented in `docs/security.md § Link-local IMDS exception`:

> The agent network isolation invariant says the agent must not call external network services. `169.254.169.254` is treated as a host-local API surface, not an external service: it never leaves the host's network stack and exists to expose cloud metadata to the local instance.

If you disagree with this carve-out — for example, because your security policy treats any non-MCP-server HTTP call as a violation — you can disable it per-host via `/etc/puck/policy-overrides.toml`. The `runtime-context` skill will then mark itself `status: degraded` and the cloud-disambiguation step will fall back to DMI-vendor inference only (which still works on most clouds via `Amazon EC2`, `Google`, `Microsoft Corporation` vendor strings — about 70% of the capability).

## Output shape

One-line classification at the top of the report:
```
Host: [container|VM|bare-metal] · [aws|azure|gcp|oci|digitalocean|on-prem|unknown] · [k8s|ecs|fargate|cloud-run|systemd|other] · service-account [present|absent]
```

Followed by per-probe evidence, a "why this matters for this investigation" framing paragraph, recommended next skills (e.g. `aws-blast-radius` if EC2-with-profile detected), and explicit blind spots.

## Known limitations

- **macOS hosts:** most Linux-specific probes don't apply. Classification is mostly "macOS laptop, not a typical cloud workload." Fewer probes run; confidence proportional.
- **Windows hosts:** not modeled in v1 (PowerShell-based detection differs from `/proc/...`).
- **IMDS blocked:** if a security group or network ACL blocks 169.254.169.254 egress, the skill cannot confirm cloud via IMDS. DMI evidence falls back.
- **IMDSv2-only EC2:** AWS instances with `HttpTokens=required` refuse IMDSv1 with 401. The skill treats 401 as a strong AWS signal even without fetching a token; no credentials are accessed.

## Composition

This skill is a precursor, not a destination:

- Outputs feed `ir-triage` (changes the "isolate or observe" calculation — a production EC2 with broad IAM ≫ a dev laptop).
- Outputs feed `aws-blast-radius` / future per-cloud blast-radius skills — they need the cloud and account context to interpret IAM credentials.
- Outputs feed `credential-exposure` — what counts as a "found credential" depends on the runtime; a kubeconfig file is expected in a pod, surprising on a laptop.

## Example invocation

```
Use puck to detect what eng-laptop-47 is — bare metal or a cloud workload —
before we decide how to interpret the alerts.
```
