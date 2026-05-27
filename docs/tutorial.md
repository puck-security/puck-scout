# Tutorial: Investigating a third-party tool breach

You just got a Slack message: Trivy, the container security scanner your team runs on build hosts, has been breached. The question isn't "are we affected?" — it's "how bad, and what do we do right now?"

By the end of this tutorial you will have run a complete investigation across your fleet and produced an `analysis.md` with the credential blast radius, specific hosts to isolate, and a rotation checklist.

**What you need**: Puck running with at least two agents enrolled. If you haven't done that, follow [Getting Started](getting-started.md) first. This tutorial uses a Linux fleet; commands adapt automatically for macOS.

---

## 1. Discover what skills are available

Open Claude Code and type:

```
What investigation skills does puck have?
```

Claude calls `puck_list_skills`. You'll see a list that includes:

```
blast-radius v1.0.0 — ir-triage
  Assess blast radius of a compromised package or vulnerability
  Duration: 3-10 minutes depending on fleet size
```

That's the skill for this scenario. It walks you through: install check → process check → credential exposure → containment recommendations.

---

## 2. Start the investigation

Type:

```
Trivy was just breached. Check our fleet for installs, see if any were 
running during the breach window, and figure out what credentials they 
had access to. Use the blast-radius skill.
```

Claude calls `puck_investigate` with your query and `skill="blast-radius"`. Puck creates an investigation (`abc-def-123`), sets up an audit log, and returns the skill's pathfinder guidance plus the list of connected agents.

You'll see something like:

```
Investigation started. I can see 12 connected agents.

I'll start with eng-build-03 — detecting the OS, checking whether Trivy 
is installed, and looking at running processes and network connections.
Before I do anything, here's my plan for that host:

  1. uname -s (detect OS and package manager)
  2. dpkg -l trivy (is it installed?)
  3. ps aux filtered for trivy (is it running?)
  4. ss -tnp (outbound connections from trivy processes)
  5. Check credential files accessible to the trivy service user
```

The skill's pathfinder guidance told Claude exactly what to check and in what order. Note that Claude announced its plan before running anything — that's the skill's checkpoint pattern.

---

## 3. Watch the pathfinder run

Claude runs the five commands on eng-build-03. Each `puck_run_check` call is audit-logged before execution. After a minute or so:

```
PATHFINDER FINDINGS — eng-build-03

Trivy 0.49.1 is installed (dpkg confirms).
Running: yes — trivy-scan process, service user trivy-svc, PID 4821.

Network connections from PID 4821:
  142.250.x.x:443  — GCS (expected, Trivy DB updates)
  185.220.101.x:443 — NOT a Trivy endpoint

Credential exposure:
  AWS_ACCESS_KEY_ID=AKIA... set in process environment
  ~/.docker/config.json readable by trivy-svc: tokens for ghcr.io, 
  ECR (us-east-1), GAR

Trivy cache last modified: within the breach window.
```

The suspicious outbound connection (185.220.101.x is a Tor exit node) and the credential exposure make this host immediately critical.

---

## 4. Approve the fleet plan

Claude pauses and asks:

```
I plan to fan out to all 12 hosts to check for Trivy installation, then 
narrow to installed hosts for process and credential checks. 

Should I also look for Docker credential files on installed hosts?
Proceed?
```

This is the checkpoint the skill requires. You're in control of what gets checked across your fleet.

Type:

```
Yes, proceed. Also check the Trivy cache modification time on any host 
where it's running.
```

---

## 5. Fleet fan-out

Claude calls `puck_get_skill_section` to retrieve the fleet strategy, then runs:

```
puck_query_fleet(hostnames=["all"], command="dpkg", args=["-l", "trivy"])
```

One call, all 12 agents in parallel, counted as 1 command. Results come back in a few seconds:

```
FLEET RESULTS — Trivy installation (12 hosts)

INSTALLED: eng-build-03, eng-build-07, dev-laptop-12, build-worker-01
CLEAN:     8 hosts

Narrowing to 4 installed hosts...
```

Claude then fans out process and credential checks to the 4 installed hosts. This is the skill's fleet strategy: install check first, then narrow — don't waste commands running deep checks on clean hosts.

---

## 6. Investigate affected hosts

Claude works through the 4 installed hosts. You see findings as they arrive:

**eng-build-03** — CRITICAL  
Running, suspicious outbound connection, AWS key in process env, Docker tokens exposed, cache modified in breach window.

**eng-build-07** — HIGH  
Running. No suspicious network connections. `~/.aws/credentials` readable by trivy-svc (different key from eng-build-03). Cache not modified.

**dev-laptop-12** — MEDIUM  
Installed, not running. No credential files accessible to Trivy's user.

**build-worker-01** — MEDIUM  
Installed, not running. No credential files accessible.

For each finding, Claude explains what it's checking and why before running the command. When it finds the AWS key in eng-build-03's process environment, it calls it out immediately — not buried in a summary.

Your investigation has used about 18 commands of the 200-command budget.

---

## 7. Save the analysis

Claude asks:

```
I've checked all 4 affected hosts. eng-build-03 needs immediate action.

Do you want me to dig deeper into the 185.220.101.x connection before 
I write the report, or shall I write it now?
```

Type:

```
Write it now. We'll handle forensics separately.
```

Claude calls `puck_get_skill_section` for `remediation_guidance` to get the containment command templates, structures the report, then calls `puck_save_analysis`.

The report lands at `investigations/abc-def-123/analysis.md`. Open it:

---

**SEVERITY: CRITICAL**

*Two hosts had Trivy running during the breach window. eng-build-03 has an active suspicious outbound connection and is the priority.*

**CONTAINMENT — do these now:**

1. **Isolate eng-build-03** from the network — the outbound connection to 185.220.101.x:443 (Tor exit node, 02:14 UTC) needs forensic review before you can rule out exfiltration. Trivy cache was modified within the breach window.

2. **Rotate the ECR key on eng-build-03** (`AKIA...`) — prod-scoped, found active in the trivy-svc process environment.

3. **Rotate Docker tokens on eng-build-03** — ghcr.io, ECR us-east-1, GAR tokens readable by trivy-svc via `~/.docker/config.json`.

4. **Rotate the AWS key on eng-build-07** (`AKIA...`, different key) — readable via `~/.aws/credentials`. No outbound IOC, but the key was exposed.

**BLAST RADIUS:**
- 12 hosts scanned
- 4 installed: eng-build-03, eng-build-07, dev-laptop-12, build-worker-01
- 2 running during breach window: eng-build-03 (critical), eng-build-07 (high)
- 2 installed, not running: dev-laptop-12, build-worker-01 (patch, no immediate credential risk)

**CREDENTIAL ROTATION CHECKLIST:**
- [ ] eng-build-03 — AWS ECR key (AKIA...) — rotated by ___
- [ ] eng-build-03 — ghcr.io token — revoked by ___
- [ ] eng-build-03 — ECR us-east-1 token — revoked by ___
- [ ] eng-build-03 — GAR token — revoked by ___
- [ ] eng-build-07 — AWS key (AKIA...) — rotated by ___

---

That's the investigation. From first prompt to saved report: under 10 minutes, ~18 commands, zero writes to any endpoint.

---

## What Puck wrote to disk

The investigation directory has everything you need for your incident record:

```
investigations/abc-def-123/
  metadata.json      # query, skill, start time, command counts
  audit.jsonl        # every command, timestamped, before execution
  analysis.md        # the report above
  pathfinder/        # raw stdout/stderr from eng-build-03
  fleet/             # raw output from all 12 hosts (install check)
  affected/          # deeper checks on the 4 installed hosts
```

The audit log is your ground truth. Every `puck_run_check` and `puck_query_fleet` call appears in `audit.jsonl` with the command, args, hostname, timestamp, and investigation ID — before execution, not after.

---

## Next steps

- **Forensics on eng-build-03**: the Tor exit connection and modified cache need a disk image and network log review before you can close the incident
- **Patch Trivy** on dev-laptop-12 and build-worker-01 once the critical rotation is done
- **Characterize the IAM blast radius**: you found two AWS key IDs. Run the `aws-blast-radius` skill to see what each principal can do:
  ```
  What is the blast radius of the key AKIA... found on eng-build-03?
  Use the aws-blast-radius skill.
  ```
- **Check your other build tooling**: if Trivy was targeted, your CI pipeline is an attractive target. Consider running the `credential-exposure` skill across your build fleet.
