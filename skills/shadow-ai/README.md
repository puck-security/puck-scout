# Shadow AI Skill

Discover unauthorized AI tools, local LLM servers, and AI provider API client usage across fleet endpoints.

## When to Use

Use this skill to inventory AI tool presence on your fleet. Common triggers:

- Compliance audit requiring documentation of AI tool usage
- Data loss prevention assessment — understanding what data may be leaving via AI APIs
- Organizational policy enforcement after an AI usage policy is introduced
- Incident investigation where AI tooling may have been used to exfiltrate data

Do NOT use this skill to block or remove AI tools. It is inventory-only — all remediation is performed by a human operator.

## How It Works

The AI checks each host across three layers: running processes (including local LLM servers listening on well-known ports), environment variables containing AI provider API keys, and configuration files or package manifests indicating AI tool installation.

A pathfinder pass on one host adapts the strategy to the OS and environment before the full fleet sweep. Hosts with active findings (running services or live API keys) get deeper investigation to establish scope and active connections.

The skill never extracts or logs API key values — it reports presence only.

## How to Interpret Results

- **Running local AI service**: Highest risk. An Ollama or similar server may be processing sensitive company data through a model without organizational oversight. Treat as a policy violation requiring immediate review.
- **AI provider API keys present**: The user has configured direct API access to an external AI provider. Risk depends on how the key is being used. Investigate which applications are using it.
- **AI tool installations (no running service)**: Lower immediate risk, but confirms the tool is available. Monitor for when it becomes active.
- **Risk levels**: High = running service or active keys. Medium = installed but not running. Low = config files only (may be stale).

You can narrow the scan with the `scope` input: `local-services` for running LLM servers only, `api-keys` for credential presence checks, or `installations` for config and package checks.

## Limitations

- Cannot detect AI tool usage that occurs entirely in a browser (e.g., ChatGPT, Claude.ai, Gemini web interface).
- API key detection is pattern-based against known provider variable names. Custom or renamed variables will be missed.
- Does not assess the content of data sent to AI providers — only that the tools are present.
- Local LLM port detection covers common defaults but custom port configurations may be missed.
- Package manifest scanning (requirements.txt, pyproject.toml) indicates the tool is a dependency, not necessarily that it is actively used.
