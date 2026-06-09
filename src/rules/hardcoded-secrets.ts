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

function scanKeyValues(
  entries: Record<string, string>,
  source: "env" | "headers",
  ctx: RuleContext,
): Finding[] {
  const { serverName, server, config } = ctx;
  const findings: Finding[] = [];

  for (const [key, value] of Object.entries(entries)) {
    if (source === "env" && SAFE_ENV_KEYS.has(key)) continue;
    if (typeof value !== "string" || value.length < 8) continue;

    const matched = detectSecret(value);
    if (matched) {
      const truncated = value.slice(0, 8) + "…";
      const sourceLabel = source === "env" ? "Environment variable" : "HTTP header";
      findings.push({
        ruleId: "hardcoded-secrets",
        severity: "critical",
        owasp: "MCP01",
        title: `Hardcoded secret detected in server ${source}`,
        description: `${sourceLabel} "${key}" in server "${serverName}" appears to contain a ${matched}.`,
        remediation: source === "env"
          ? `Set the value as a system environment variable (e.g., export ${key}=<value> in ~/.zshrc), then remove it from the MCP config. If your client supports env var references, use \${${key}} in the config instead of the raw value.`
          : `Move the "${key}" header value to a secure credential store. Use a reverse proxy or gateway to inject auth headers at runtime instead of hardcoding them in the MCP config.`,
        client: config.client,
        configPath: config.configPath,
        serverName,
        evidence: `${key}=${truncated}`,
      });
    }
  }

  return findings;
}

function check(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  if (ctx.server.env) {
    findings.push(...scanKeyValues(ctx.server.env, "env", ctx));
  }

  if (ctx.server.headers) {
    findings.push(...scanKeyValues(ctx.server.headers, "headers", ctx));
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
