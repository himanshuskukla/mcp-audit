# mcp-audit

Security scanner for MCP configurations — npm audit for the AI agent era

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node >= 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)

Scans MCP client configs for hardcoded secrets, dangerous commands, missing TLS, unsafe auto-install, excessive permissions, Docker misconfigurations, sensitive path exposure, environment leakage, and shadow servers. Optionally connects to live MCP servers to detect tool poisoning and missing logging. Maps every finding to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/). Covers 8 of 10 OWASP categories.

## Quick start

```bash
npx mcp-audit
```

Automatically detects and scans all MCP clients installed on the current machine. No API keys, no accounts, runs entirely offline.

For a deeper scan that connects to your MCP servers and inspects tool schemas:

```bash
npx mcp-audit --live
```

## What it checks

### Static rules (config analysis — instant)

| Rule | OWASP | Severity | What it detects |
|---|---|---|---|
| `hardcoded-secrets` | MCP01 | CRITICAL | 11 secret patterns in env blocks (OpenAI, Anthropic, GitHub, AWS, Slack, Stripe, DB URLs, Google, Notion, generic) |
| `dangerous-commands` | MCP05 | HIGH | Shell interpreters (bash, sh, zsh, cmd, powershell) as commands + shell metacharacters in args |
| `missing-tls` | MCP07 | HIGH | HTTP URLs for remote MCP servers (localhost is allowed) |
| `docker-sandboxing` | MCP02 | HIGH | `--privileged`, missing `--read-only`, dangerous volume mounts, missing network isolation |
| `sensitive-paths` | MCP02 | HIGH | ~/.ssh, ~/.aws, ~/.kube, ~/.gnupg, .env files in server args |
| `npx-auto-install` | MCP06 | MEDIUM | `npx -y` auto-installs packages without verification |
| `excessive-permissions` | MCP02 | MEDIUM | Root `/`, home directory, or system paths in server args |
| `env-leakage` | MCP01 | MEDIUM | No env block (inherits full process environment) + sensitive variable passthrough |
| `shadow-servers` | MCP09 | MEDIUM | Same server name across multiple MCP clients (cross-config) |

### Live rules (`--live` — connects to servers)

| Rule | OWASP | Severity | What it detects |
|---|---|---|---|
| `tool-poisoning` | MCP03 | CRITICAL | Hidden instructions, data exfiltration hints, excessive scope claims, suspicious Unicode in tool descriptions |
| `logging-check` | MCP10 | MEDIUM | Servers with no logging or audit capability |

## Supported clients (12)

Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, LM Studio, VS Code RooCode, VS Code Augment, Zed, Amazon Q Developer, Cline

Run `mcp-audit clients` to see all config paths for your OS.

## CLI usage

```
mcp-audit [options] [command]

Options:
  -V, --version          Show version
  -f, --format <format>  Output format: terminal (default) or json
  -c, --config <path>    Scan a specific config file
  --client <name>        Client name when using --config
  --live                 Connect to MCP servers and inspect tool schemas
  --no-color             Disable colored output
  --strict               Exit with code 1 if any findings (CI mode)
  -h, --help             Show help

Commands:
  clients                List all supported MCP clients and their config paths
```

### Examples

```bash
# Scan all detected clients
npx mcp-audit

# Deep scan — also connect to servers and check tool schemas
npx mcp-audit --live

# Scan a specific config file
npx mcp-audit --config ~/.cursor/mcp.json

# JSON output for CI pipelines
npx mcp-audit --format json

# Fail CI if any findings
npx mcp-audit --strict

# List supported clients and config paths
npx mcp-audit clients
```

## Example output

```
mcp-audit — MCP Security Scanner
────────────────────────────────────────────────────────────

Claude Code (6 servers)
  ~/.claude.json
  1. CRITICAL [MCP01] Hardcoded secret detected in server environment
     server: magic
     Description: Environment variable "API_KEY" in server "magic" appears to contain a Generic Secret.
     Evidence:    API_KEY=18d30364…
     Remediation: Set the value as a system environment variable (e.g., export API_KEY=<value>
                  in ~/.zshrc), then remove it from the MCP config.
  2. MEDIUM [MCP06] npx used with auto-install flag
     server: magic
     Description: Server "magic" uses "npx" with the "-y" flag, which automatically installs
                  packages without confirmation.
     Remediation: Install the package first: npm install -g @21st-dev/magic@latest.

  Summary: 2 findings (1 CRITICAL, 1 MEDIUM)

────────────────────────────────────────────────────────────
Findings Summary

┌──────────┬───────┬─────────────────┬─────────────────┬──────────────────────────────────────────┐
│ Severity │ OWASP │ Client          │ Server          │ Issue                                    │
├──────────┼───────┼─────────────────┼─────────────────┼──────────────────────────────────────────┤
│ CRITICAL │ MCP01 │ Claude Code     │ magic           │ Hardcoded secret detected in server env… │
│ MEDIUM   │ MCP06 │ Claude Code     │ magic           │ npx used with auto-install flag          │
└──────────┴───────┴─────────────────┴─────────────────┴──────────────────────────────────────────┘

Security Score: 70/100 (C — Needs Attention)
```

## Security score

Every scan produces a security score from 0-100 with a letter grade:

| Score | Grade | Meaning |
|---|---|---|
| 90-100 | A | Excellent |
| 75-89 | B | Good |
| 50-74 | C | Needs Attention |
| 25-49 | D | Poor |
| 0-24 | F | Critical Risk |

Scoring: CRITICAL = -25, HIGH = -15, MEDIUM = -5, LOW = -2. The score gives teams a single number to track security posture over time.

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
| `strict` | `true` | Fail the workflow if any findings |

## OWASP MCP Top 10 coverage

| OWASP | Category | Covered | Rule |
|---|---|---|---|
| MCP01 | Token Mismanagement | Yes | hardcoded-secrets, env-leakage |
| MCP02 | Scope Creep | Yes | excessive-permissions, docker-sandboxing, sensitive-paths |
| MCP03 | Tool Poisoning | Yes | tool-poisoning (`--live`) |
| MCP04 | Intent Flow Subversion | - | Requires runtime proxy |
| MCP05 | Command Injection | Yes | dangerous-commands |
| MCP06 | Insecure Dependencies | Yes | npx-auto-install |
| MCP07 | Insufficient Auth | Yes | missing-tls |
| MCP08 | Context Over-Sharing | - | Requires runtime proxy |
| MCP09 | Shadow Servers | Yes | shadow-servers |
| MCP10 | Insufficient Logging | Yes | logging-check (`--live`) |

8 of 10 categories covered. MCP04 and MCP08 require a persistent runtime proxy — planned for a future release.

## Contributing

1. Fork the repository.
2. Run `npm ci && npm test` to verify the baseline (128 tests).
3. Add or update a rule in `src/rules/` or `src/live/`, with a matching test.
4. Open a pull request — CI must pass.

Bug reports and rule suggestions are welcome via GitHub Issues.

## License

MIT
