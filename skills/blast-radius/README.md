# Blast Radius Skill

Assess the blast radius of a compromised package or actively exploited vulnerability across your fleet.

## When to Use

Use this skill when you have a specific package compromise or CVE and need to understand fleet-wide exposure. Typical triggers:

- A supply chain compromise is announced for a package your fleet uses
- An actively exploited CVE is disclosed and you need to know which hosts are running the vulnerable version
- Post-incident: understanding how far a compromised dependency reached

Do NOT use this skill for general CVE scanning across many CVEs at once — use the `cve-exposure` skill for that. This skill is for depth: one package or CVE, investigated thoroughly.

## How It Works

The skill uses a pathfinder-then-fleet approach:

1. **Pathfinder phase**: The AI investigates one representative host to understand what evidence of the package looks like (install paths, process names, config files, network patterns).
2. **Fleet phase**: Using that knowledge, it runs targeted checks across all reachable hosts.
3. **Deep dive**: Hosts where the package is installed AND running get additional investigation for active connections and credential exposure.

The AI composes all commands from the embedded policy grammar — it is not limited to a fixed set of steps.

## How to Interpret Results

- **Installed vs. running**: A package being installed is less urgent than one actively running. Running processes with network connections are the highest priority.
- **Network connections**: Unexpected outbound connections from an affected process may indicate active exploitation.
- **Credential exposure**: Any credentials accessible to the affected package process should be treated as potentially compromised.
- **Containment actions**: The skill produces recommendations, but containment (killing processes, isolating hosts, rotating credentials) must be performed by a human operator.

## Limitations

- Assessment quality depends on the AI's ability to identify the package from the query. Be specific: include the package name and CVE ID if known.
- Hosts without the Puck agent installed cannot be assessed.
- The skill cannot determine whether exploitation has already occurred — only whether the conditions for exploitation exist.
- Credential exposure detection is heuristic. Not all credential stores are enumerable.
