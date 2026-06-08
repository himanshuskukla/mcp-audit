import { homedir } from "node:os";
import { registerRule } from "./index.js";
import type { Finding, RuleContext } from "./types.js";

const DANGEROUS_PATHS = new Set([
  "/",
  "/etc",
  "/var",
  "/usr",
  "/tmp",
  "/root",
  "C:\\",
  "C:\\Windows",
]);

function isDangerousPath(arg: string): boolean {
  if (DANGEROUS_PATHS.has(arg)) return true;
  const home = homedir();
  if (arg === home) return true;
  return false;
}

function check(ctx: RuleContext): Finding[] {
  const { serverName, server, config } = ctx;
  if (!server.args || server.args.length === 0) return [];

  const findings: Finding[] = [];

  for (const arg of server.args) {
    if (isDangerousPath(arg)) {
      findings.push({
        ruleId: "excessive-permissions",
        severity: "high",
        owasp: "MCP02",
        title: "Server granted overly broad filesystem access",
        description: `Server "${serverName}" is configured with argument "${arg}", which grants access to a sensitive or overly broad filesystem path.`,
        remediation:
          "Restrict filesystem access to the minimum required directory. Avoid granting access to system directories or the entire home folder.",
        client: config.client,
        configPath: config.configPath,
        serverName,
        evidence: `arg=${arg}`,
      });
    }
  }

  return findings;
}

registerRule({
  id: "excessive-permissions",
  name: "Excessive Filesystem Permissions",
  owasp: "MCP02",
  severity: "high",
  check,
});
