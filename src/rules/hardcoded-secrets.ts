import { detectSecret } from "../utils/secrets-patterns.js";
import { registerRule } from "./index.js";
import type { Finding, RuleContext } from "./types.js";

const SAFE_ENV_KEYS = new Set([
  "NODE_ENV",
  "PORT",
  "HOST",
  "PATH",
  "HOME",
  "LANG",
  "SHELL",
  "TERM",
  "USER",
  "LOGNAME",
  "DISPLAY",
  "TZ",
  "LC_ALL",
  "PYTHONPATH",
  "PYTHONUNBUFFERED",
  "DEBUG",
  "LOG_LEVEL",
  "VERBOSE",
]);

function check(ctx: RuleContext): Finding[] {
  const { serverName, server, config } = ctx;
  if (!server.env) return [];

  const findings: Finding[] = [];

  for (const [key, value] of Object.entries(server.env)) {
    if (SAFE_ENV_KEYS.has(key)) continue;
    if (typeof value !== "string" || value.length < 8) continue;

    const matched = detectSecret(value);
    if (matched) {
      const truncated = value.slice(0, 8) + "…";
      findings.push({
        ruleId: "hardcoded-secrets",
        severity: "critical",
        owasp: "MCP01",
        title: "Hardcoded secret detected in server environment",
        description: `Environment variable "${key}" in server "${serverName}" appears to contain a ${matched}.`,
        remediation:
          `Set the value as a system environment variable (e.g., export ${key}=<value> in ~/.zshrc), then remove it from the MCP config. If your client supports env var references, use \${${key}} in the config instead of the raw value.`,
        client: config.client,
        configPath: config.configPath,
        serverName,
        evidence: `${key}=${truncated}`,
      });
    }
  }

  return findings;
}

registerRule({
  id: "hardcoded-secrets",
  name: "Hardcoded Secrets in Environment",
  owasp: "MCP01",
  severity: "critical",
  check,
});
