# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Puck, please report it responsibly.

**Email**: security@puck.security

**Response time**: We will acknowledge receipt within 48 hours and provide an initial assessment within 5 business days.

**What to include**:
- Description of the vulnerability
- Steps to reproduce
- Affected component (agent, MCP server, skills)
- Potential impact assessment

## Scope

The following are in scope for security reports:
- The Puck endpoint agent (Rust)
- The Puck MCP server (Go)
- The skills schema and validation
- The CI/CD pipeline security

The following are out of scope:
- Vulnerabilities in MCP clients (Claude Code, Cursor, etc.)
- Vulnerabilities in AI model providers (Anthropic, OpenAI, etc.)
- Social engineering attacks

## Disclosure Policy

- We do not currently operate a bug bounty program.
- We will publicly credit researchers who disclose vulnerabilities responsibly, unless they request anonymity.
- We ask that you give us reasonable time to address the vulnerability before public disclosure.
- We will coordinate disclosure timing with you.

## Security Design

For information about Puck's security model, trust boundaries, and threat model, see [docs/security.md](docs/security.md).
