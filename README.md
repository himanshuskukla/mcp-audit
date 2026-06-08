# mcp-audit

Security scanner for MCP configurations — npm audit for the AI agent era

[![npm version](https://img.shields.io/npm/v/mcp-audit)](https://www.npmjs.com/package/mcp-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node >= 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)

Scans MCP client configuration files for hardcoded secrets, dangerous shell commands, missing TLS, unsafe package auto-install, and excessive filesystem permissions. Maps every finding to the [OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

## Quick start

```bash
npx mcp-audit
```

Automatically detects and scans all MCP clients installed on the current machine.

## What it checks

| Rule | OWASP | Severity | Description |
|---|---|---|---|
| `hardcoded-secrets` | MCP01 | CRITICAL | API keys, tokens, and credentials embedded in config (OpenAI, Anthropic, GitHub, AWS, Slack, Stripe, database URLs, Google, Notion, and generic patterns) |
| `excessive-permissions` | MCP02 | MEDIUM | Overly broad filesystem access (root `/`, home directory, or `--allow-write=/`) |
| `dangerous-commands` | MCP05 | HIGH | Shell interpreters (`bash`, `sh`, `zsh`, `python`, `node`) used as MCP commands, or shell metacharacters in arguments |
| `npx-auto-install` | MCP06 | MEDIUM | `npx -y` flag silently installs packages without confirmation |
| `missing-tls` | MCP07 | HIGH | Remote MCP server URLs using plain `http://` instead of `https://` |

## Supported clients

- Claude Desktop
- Claude Code
- Cursor
- VS Code
- VS Code RooCode
- VS Code Augment
- Windsurf
- Gemini CLI
- LM Studio
- Zed
- Amazon Q Developer
- Cline

## CLI usage

```
mcp-audit [options] [command]

Options:
  --config <path>       Scan a specific config file instead of auto-detecting
  --format <fmt>        Output format: terminal (default) or json
  --strict              Exit with code 1 if any findings are found (CI mode)
  -h, --help            Show help

Commands:
  clients               List all supported MCP clients and their config paths
```

### Examples

```bash
# Scan all detected clients
npx mcp-audit

# Scan a specific config file
npx mcp-audit --config ~/.cursor/mcp.json

# JSON output
npx mcp-audit --format json

# CI mode — fails if any findings
npx mcp-audit --strict

# List supported clients and config paths
npx mcp-audit clients
```

## Example output

```
mcp-audit v0.1.0

Scanning Claude Desktop (/Users/user/Library/Application Support/Claude/claude_desktop_config.json)

  CRITICAL  hardcoded-secrets  MCP01
  Server:   github-tools
  Match:    ghp_xxxxxxxxxxxxxxxxxxxx
  Field:    env.GITHUB_TOKEN
  Fix:      Move secrets to environment variables or a secrets manager.

  HIGH      missing-tls        MCP07
  Server:   my-remote-server
  Match:    http://localhost:8080
  Field:    url
  Fix:      Use https:// for all remote server URLs.

Findings: 2 (1 critical, 1 high, 0 medium)
```

## JSON output format

```bash
npx mcp-audit --format json
```

```json
{
  "version": "0.1.0",
  "scannedAt": "2026-06-08T12:00:00.000Z",
  "clients": [
    {
      "name": "Claude Desktop",
      "configPath": "/Users/user/Library/Application Support/Claude/claude_desktop_config.json",
      "findings": [
        {
          "rule": "hardcoded-secrets",
          "owasp": "MCP01",
          "severity": "critical",
          "server": "github-tools",
          "field": "env.GITHUB_TOKEN",
          "match": "ghp_xxxxxxxxxxxxxxxxxxxx",
          "fix": "Move secrets to environment variables or a secrets manager."
        }
      ]
    }
  ],
  "summary": {
    "total": 1,
    "critical": 1,
    "high": 0,
    "medium": 0
  }
}
```

## GitHub Action

```yaml
- name: Audit MCP configuration
  uses: himanshuskukla/mcp-audit@v1
  with:
    strict: true
```

### Inputs

| Input | Default | Description |
|---|---|---|
| `config` | (auto-detect) | Path to a specific MCP config file |
| `format` | `terminal` | Output format: `terminal` or `json` |
| `strict` | `true` | Fail the workflow if any findings are found |

### Full workflow example

```yaml
name: Security audit
on: [push, pull_request]
jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Audit MCP configuration
        uses: himanshuskukla/mcp-audit@v1
        with:
          config: .mcp.json
          strict: true
```

## Contributing

1. Fork the repository.
2. Run `npm ci && npm test` to verify the baseline.
3. Add or update a rule in `src/rules/`, with a matching test in `tests/`.
4. Open a pull request — CI must pass.

Bug reports and rule suggestions are welcome via GitHub Issues.

## License

MIT
