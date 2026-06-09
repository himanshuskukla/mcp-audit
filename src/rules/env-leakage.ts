import { registerRule } from "./index.js";
import type { Finding, RuleContext } from "./types.js";

const SENSITIVE_ENV_VARS = new Set([
  "AWS_SECRET_ACCESS_KEY",
  "AWS_ACCESS_KEY_ID",
  "AWS_SESSION_TOKEN",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GITLAB_TOKEN",
  "DATABASE_URL",
  "REDIS_URL",
  "MONGODB_URI",
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "STRIPE_SECRET_KEY",
  "PRIVATE_KEY",
  "SECRET_KEY",
  "JWT_SECRET",
]);

function isStdioServer(server: RuleContext["server"]): boolean {
  return !!server.command && !server.url && !server.serverUrl;
}

function check(ctx: RuleContext): Finding[] {
  const { serverName, server, config } = ctx;

  // Only applies to stdio servers
  if (!isStdioServer(server)) return [];

  const findings: Finding[] = [];

  // Check 1: No env block at all → inherits full parent environment
  if (server.env === undefined) {
    findings.push({
      ruleId: "env-leakage",
      severity: "medium",
      owasp: "MCP01",
      title: "Server inherits full process environment",
      description: `Server "${serverName}" has no "env" block defined. It will inherit the entire parent process environment, potentially exposing secrets present in the shell session (e.g. API keys, tokens, database URLs).`,
      remediation:
        'Add an explicit "env": {} block to the server config. This gives the server a clean environment. Then add ONLY the specific variables it needs, e.g., "env": { "NODE_ENV": "production" }.',
      client: config.client,
      configPath: config.configPath,
      serverName,
      evidence: `env block absent`,
    });
  }

  // Check 2: env block explicitly passes known-sensitive variable names
  if (server.env) {
    for (const key of Object.keys(server.env)) {
      if (SENSITIVE_ENV_VARS.has(key)) {
        findings.push({
          ruleId: "env-leakage",
          severity: "medium",
          owasp: "MCP01",
          title: "Sensitive variable explicitly passed to server",
          description: `Server "${serverName}" explicitly passes the sensitive environment variable "${key}" to the MCP server process. Even if the value is a reference, forwarding this variable expands its exposure surface.`,
          remediation:
            `Remove "${key}" from the env block. If the server needs this credential, create a dedicated API key with minimal permissions rather than passing your personal/admin credential.`,
          client: config.client,
          configPath: config.configPath,
          serverName,
          evidence: `env key: ${key}`,
        });
      }
    }
  }

  return findings;
}

registerRule({
  id: "env-leakage",
  name: "Environment Variable Leakage",
  owasp: "MCP01",
  severity: "medium",
  check,
});
