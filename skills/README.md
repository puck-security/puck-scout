# Puck Skills Library

Investigation playbooks as YAML + markdown. Skills are the source of truth for how Puck conducts investigations.

## Available Skills

| Skill | Category | Description |
|-------|----------|-------------|
| [ir-triage](ir-triage/) | ir-triage | Initial incident response triage for a suspicious endpoint |
| [blast-radius](blast-radius/) | ir-triage | Scope lateral movement and determine blast radius |
| [shadow-ai](shadow-ai/) | inventory | Discover unauthorized AI tools and services |
| [cve-exposure](cve-exposure/) | compliance | Check endpoint exposure to specific CVEs |

## Contributing a Skill

See [docs/contributing.md](../docs/contributing.md) and [skills/CLAUDE.md](CLAUDE.md).

Skills must validate against the [JSON Schema](schema/skill-schema.json).

## Status

All skills are currently stubs pending agent and MCP server implementation.
