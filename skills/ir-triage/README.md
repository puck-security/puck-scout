# IR Triage Skill

Perform initial incident response triage on a suspicious endpoint.

## When to Use

Use this skill as the first step in any endpoint investigation. Typical triggers:

- An EDR or SIEM alert fires on a host and you need a rapid severity assessment
- A user reports suspicious behavior on their machine
- You need to determine whether a host warrants deeper investigation before escalating

This is a breadth-first skill. It checks processes, network connections, authentication logs, scheduled tasks, and persistence locations to build an overall picture quickly. If findings indicate active compromise, escalate to `blast-radius` for lateral movement or `cve-exposure` for specific vulnerability confirmation.

Do NOT use this skill when you already know the specific indicator you are hunting for — use a more targeted skill instead.

## How It Works

The AI examines the target host across five investigation areas in order: processes, network connections, authentication events, scheduled tasks, and recently modified files. It adapts depth based on findings — spending more time where suspicious indicators appear and less time where things look clean.

This skill does not fan out to other hosts. If lateral movement is suspected, the AI will recommend running `blast-radius` as a follow-on.

## How to Interpret Results

- **Severity critical/high**: Active compromise indicators present. Escalate immediately. Consider isolating the host.
- **Severity medium**: Suspicious but ambiguous indicators. Deeper investigation warranted before escalating.
- **Severity low/informational**: Nothing clearly malicious found. Document and close, or continue monitoring.
- **Follow-on skills**: The report will recommend which skills to run next based on findings. Follow those recommendations.

Providing alert context (the `alert_context` input) helps the AI focus its investigation. For example: "EDR alert: process explorer.exe spawned cmd.exe" will focus more attention on process lineage.

## Limitations

- Triage is not forensics. This skill identifies indicators of compromise, not root cause.
- On endpoints with high process or connection counts, the AI will prioritize by suspicion level rather than enumerate everything.
- Authentication log formats vary by OS. Coverage is best on Linux (syslog/journald) and macOS (unified log). Windows event log support depends on agent capabilities.
- This skill does not isolate hosts or take any containment action. All response actions must be performed by a human operator.
