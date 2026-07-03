# aws-blast-radius

Characterizes AWS principals from discovered AccessKeyIds. Given the
output of `credential-exposure` (or any other source of AKIA/ASIA
values), the skill produces a per-principal blast-radius assessment:
which account, which IAM user or role, what policies are attached,
when the key was last used, what dangerous actions the principal can
effectively perform, and what API calls the key has been making in the
recent past.

## When to use

After a `credential-exposure` run that surfaced one or more
AccessKeyIds and you want to know:

- Which IAM user or role does each key belong to?
- Is the key actively in use, or stale?
- Can this principal escalate to admin? Can it read secrets, delete
  data, terminate compute, or stop CloudTrail logging?
- What has this key actually done in the last 7 days?

This is an IR-triage skill — the output is "rotate these N keys in
this order, and assume each one has already touched these resources."

## Operating envelope

- **Read-only AWS APIs only.** No `create-*`, no `delete-*`, no
  `attach-*`, no `put-*`, no `assume-role`. The MCP allowlist enforces
  this; the skill cannot mutate state.
- **The agent uses its own AWS auth, not the discovered key.** We
  treat the discovered AccessKeyId as compromised; there's no point in
  test-driving it. The agent must have IAM read permissions in the
  account where the key lives for deep enumeration; otherwise the
  result is degraded but still includes account attribution.
- **Operator-invoked.** The skill is not autonomously chained from
  any other skill. `credential-exposure` surfaces AccessKeyIds; the
  responder makes the explicit call to run blast-radius on them. This
  is a deliberate design constraint — agents do not initiate network
  activity to upstream identity providers without explicit user
  opt-in.
- **CloudTrail side effect.** Calls made by this skill are recorded
  in CloudTrail under the agent's own principal. That's expected for
  an explicitly-invoked IR workflow and matches what the responder
  would log running these calls from the console.

## Inputs

| Input | Type | Default | Notes |
|---|---|---|---|
| `query` | string | required | Free-form context. If `access_key_ids` is empty, the AI parses this for AKIA/ASIA values. |
| `access_key_ids` | string[] | — | The set of keys to investigate. Typically pasted from a credential-exposure report. |
| `principal_arns` | string[] | — | Direct IAM user/role ARNs when the AccessKeyId is unknown (e.g. ASIA temporary creds — investigate the parent role instead). |
| `sso_cache_paths` | string[] | — | Paths to `~/.aws/sso/cache/*.json` files surfaced by credential-exposure. Phase 7 reads these to extract `expiresAt`, `accountId`, `roleName`, and `startUrl` for session-validity classification. (v1.1.0) |
| `prod_account_ids` | string[] | — | Operator-declared production AWS account IDs. Forces `PROD-DECLARED` classification regardless of role name heuristics. (v1.1.0) |
| `dev_account_ids` | string[] | — | Operator-declared dev/sandbox AWS account IDs. Forces `DEV-DECLARED` classification — defaults toward INFO for routine engineer activity. (v1.1.0) |
| `simulate` | boolean | true | Run `iam simulate-principal-policy` to compute effective dangerous actions. |
| `cloudtrail` | boolean | true | Run `cloudtrail lookup-events` to surface recent activity. |
| `time_range_days` | number | 7 | CloudTrail lookback window. |

### Don't cry wolf

Engineers routinely have valid SSO sessions on their endpoints; that
is how they do their work with the AWS CLI. The skill's severity
defaults reflect this — an ACTIVE SSO session is **not** automatically
CRITICAL. Severity combines three dimensions:

1. **Authority** — what the principal can do (Admin / Power / IAM-Full
   vs. scoped / read-only).
2. **Session validity** — can the credential be used right now
   (ACTIVE), or is it latent until the user re-authenticates (EXPIRED)?
3. **Account context** — declared prod, declared dev, role-name
   heuristic guess, or genuinely UNCLEAR.

The most-CRITICAL finding only fires when all three line up:
**ACTIVE + Admin authority + PROD-DECLARED account**. Active
non-admin sessions in declared-dev accounts default to `INFO` —
recorded but no action expected. EXPIRED sessions never produce
CRITICAL or HIGH; their remediation lives on a different clock
(rotate or revoke access **before** the legitimate user runs
`aws sso login` again).

For analysts who want fewer findings, populate `prod_account_ids` and
`dev_account_ids` once and the skill stops guessing.

## Phases

1. **Agent context** — `aws sts get-caller-identity` records the
   account and principal the agent operates under. Defines the
   "deep-investigatable" boundary.
2. **Per-key account attribution** — `aws sts get-access-key-info`
   returns the account ID for any AccessKeyId, even cross-account.
   Splits the input into same-account (full enumeration) vs.
   cross-account (account ID only, escalate to operator).
3. **Same-account principal attribution** — `aws iam
   get-access-key-last-used` returns the IAM user, last-used
   timestamp, service, region.
4. **Policy enumeration** — managed and inline policies, both
   attached and bodies. Highlights AdministratorAccess /
   PowerUserAccess / IAMFullAccess and any inline `"Action":"*"` /
   `"Resource":"*"` statements. Reads permissions boundary if set.
5. **Effective dangerous-action simulation** (gated on `simulate`)
   — `aws iam simulate-principal-policy` against an opinionated
   action list (IAM persistence, S3 destruction, secret retrieval,
   compute manipulation, CloudTrail tampering, log destruction).
   Returns the actual subset of dangerous actions the principal can
   perform after policy evaluation, accounting for inline + managed +
   permissions boundary.
6. **Recent CloudTrail activity** (gated on `cloudtrail`) — `aws
   cloudtrail lookup-events --lookup-attributes
   AttributeKey=AccessKeyId,…`. Returns the events the key has issued
   in the lookback window. The skill summarizes top EventNames,
   error rate, distinct source IPs, distinct regions, notable
   resources (bucket names, secret ARNs, etc.), and classifies the
   pattern as Stale / Dormant / Routine / Diverse / Suspicious.
7. **Session validity & context classification** (v1.1.0; runs when
   `sso_cache_paths` is non-empty OR any AccessKeyId starts with
   `ASIA`) — reads the SSO cache file via `cat`, extracts
   `expiresAt`/`accountId`/`roleName`/`startUrl`, computes ACTIVE vs.
   EXPIRED, and classifies the account as PROD-DECLARED /
   DEV-DECLARED / PROD-HEURISTIC / DEV-HEURISTIC / UNCLEAR. Drives
   the session-bearing severity matrix. Distinguishes session cache
   entries (have `accessToken` + `roleName`) from registration cache
   entries (have `clientId` + `clientSecret`, no `roleName`) — the
   latter is a device-binding artifact, flagged separately at MEDIUM.

## Severity (v1.1.0)

Severity differs for long-lived IAM keys (AKIA) vs. session-bearing
credentials (ASIA / SSO).

### Long-lived IAM keys

| Tier | Criteria |
|---|---|
| CRITICAL | AdministratorAccess attached; OR effective allowed actions include `iam:*` / `s3:Delete*` / `kms:Decrypt` / `secretsmanager:GetSecretValue` AND key was used in the last 24h |
| HIGH | Effective dangerous actions present but key is stale (>30d); OR PowerUserAccess; OR broad service-level grants in inline policy |
| MEDIUM | No admin / persistence permissions; key last-used >30d; bounded scope policies |
| INFO | `iam get-access-key-last-used` returns NoSuchEntity (key already revoked) |

### Session-bearing credentials (ASIA / SSO)

Severity matrix; the EXPIRED column never produces CRITICAL or HIGH.

| Authority | Context | ACTIVE | EXPIRED |
|---|---|---|---|
| Admin / Power / IAM-Full | PROD-DECLARED | **CRITICAL** | MEDIUM |
| | PROD-HEURISTIC | HIGH | MEDIUM |
| | UNCLEAR | HIGH | LOW |
| | DEV-HEURISTIC | MEDIUM | LOW |
| | DEV-DECLARED | MEDIUM | INFO |
| Bounded / scoped | PROD-DECLARED | MEDIUM | LOW |
| | PROD-HEURISTIC | MEDIUM | LOW |
| | UNCLEAR | LOW | INFO |
| | DEV-HEURISTIC | INFO | INFO |
| | DEV-DECLARED | INFO | INFO |

Every per-principal finding carries an explicit `Severity:` line and a
`Why:` line that names the three contributing dimensions. Bare
severity letters are a defect — analysts should never wonder why.

### Other tiers

| Tier | Criteria |
|---|---|
| INCONCLUSIVE-CROSS-ACCOUNT | Key belongs to a different account than the agent's own auth. Surface account ID + AccessKeyId; operator escalates to a console session in the right account. |

## Composition with credential-exposure

`credential-exposure` (v1.2.1+) surfaces AccessKeyIds in full as
identifier-class fields, in the "Detailed Findings" section's
`Identifiers` row. The responder can copy them into this skill's
`access_key_ids` input or paste them into the query:

```
Investigate AKIAEXAMPLE12345678 and AKIAEXAMPLE87654321 with
aws-blast-radius. They came from the prior credential-exposure
run on host eng-laptop-47.
```

The two skills are not autonomously chained — by design — to keep the
"no autonomous network activity" boundary clear.

Companion tool: [`geiger --live`](https://github.com/puck-security/geiger)
is the operator-side one-shot for a fast liveness + capability read on a
key, and the way to triage NON-AWS credentials surfaced alongside AWS
ones. It runs read-only and out-of-band (not through Puck); this skill
remains the deep AWS-IAM characterization. See the credential-exposure
README's "Companion tool: geiger" section.

## Required allowlist additions

`mcp/puck-mcp.yaml` for v1.0.0 includes the following AWS read-only
subcommands. The matcher accepts any trailing flags (`--profile`,
`--region`, `--output`, etc.) on these.

```yaml
allowed_subcommands:
  aws:
    - "sts get-caller-identity"
    - "sts get-access-key-info"
    - "iam list-roles"
    - "iam list-users"
    - "iam get-user"
    - "iam get-role"
    - "iam get-access-key-last-used"
    - "iam list-attached-user-policies"
    - "iam list-user-policies"
    - "iam get-user-policy"
    - "iam list-attached-role-policies"
    - "iam list-role-policies"
    - "iam get-role-policy"
    - "iam get-policy"
    - "iam get-policy-version"
    - "iam simulate-principal-policy"
    - "cloudtrail lookup-events"
    # plus existing s3 ls / ec2 describe-instances / logs describe-log-groups
```

Mutating subcommands (`iam create-*`, `iam delete-*`, `iam attach-*`,
`iam detach-*`, `iam put-*`, `iam update-*`, `sts assume-role*`,
`cloudtrail delete-trail`, `cloudtrail stop-logging`) are NOT in the
allowlist and are rejected by the matcher.

## Limitations

- ASIA temporary STS credentials don't have an
  `iam get-access-key-last-used` record. Pass the parent role's ARN
  via `principal_arns` to investigate ASIA keys.
- Cross-account keys can be attributed to an account ID via
  `sts get-access-key-info` but cannot be deeply enumerated without
  auth in the target account. The operator must escalate to a
  console session or assume-role into the target account and re-run
  the skill from an agent with that auth.
- CloudTrail lookup-events has a tighter rate limit than IAM (~2 TPS
  / 1500 per hour per account). For >5 keys the skill paces calls; for
  very large key sets, consider running the skill in batches.
- The `simulate` action set is opinionated and not exhaustive. It
  catches the most common dangerous-action classes (admin escalation,
  data destruction, secret retrieval, log tampering) but a custom
  threat model may want different actions — override via
  `simulate_actions` (planned for a future version).

## Sibling skills (planned, not yet implemented)

The same shape applies to other identity providers. Future skills:

- `gcp-blast-radius` — service account key + projects.iam queries
- `azure-blast-radius` — managed identity / service principal lookups
- `github-blast-radius` — PAT / fine-grained token scope enumeration
  via `gh api` and the GitHub REST API
- `gitlab-blast-radius` — same pattern via GitLab API

Each will live in its own skills directory with its own allowlist
additions and prompt-language; this AWS skill is the prototype.
