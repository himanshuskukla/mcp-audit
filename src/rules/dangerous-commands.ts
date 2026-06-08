import { registerRule } from "./index.js";
import type { Finding, RuleContext } from "./types.js";

const DANGEROUS_COMMANDS = new Set([
  "bash",
  "sh",
  "zsh",
  "cmd",
  "cmd.exe",
  "powershell",
  "pwsh",
]);

const SHELL_METACHAR_PATTERN =
  /[;|&`$(){}]|\brm\s+-rf\b|\bcurl\b.*\|\s*(?:sh|bash)/;

function check(ctx: RuleContext): Finding[] {
  const { serverName, server, config } = ctx;
  const findings: Finding[] = [];

  // Check 1: command is a shell interpreter
  if (server.command && DANGEROUS_COMMANDS.has(server.command)) {
    findings.push({
      ruleId: "dangerous-commands",
      severity: "high",
      owasp: "MCP05",
      title: "Server uses a shell interpreter as command",
      description: `Server "${serverName}" uses "${server.command}" as its command, which is a shell interpreter. This can allow arbitrary code execution.`,
      remediation:
        "Use a specific executable instead of a shell interpreter. Avoid invoking shells directly.",
      client: config.client,
      configPath: config.configPath,
      serverName,
      evidence: `command=${server.command}`,
    });
  }

  // Check 2: args contain shell metacharacters or dangerous patterns
  if (server.args && server.args.length > 0) {
    const argsStr = server.args.join(" ");
    if (SHELL_METACHAR_PATTERN.test(argsStr)) {
      findings.push({
        ruleId: "dangerous-commands",
        severity: "high",
        owasp: "MCP05",
        title: "Server arguments contain shell metacharacters",
        description: `Server "${serverName}" has arguments containing shell metacharacters or dangerous patterns, which may indicate command injection risk.`,
        remediation:
          "Avoid shell metacharacters in arguments. Use parameterized invocation instead of shell command strings.",
        client: config.client,
        configPath: config.configPath,
        serverName,
        evidence: `args=${argsStr.slice(0, 60)}`,
      });
    }
  }

  return findings;
}

registerRule({
  id: "dangerous-commands",
  name: "Dangerous Shell Commands",
  owasp: "MCP05",
  severity: "high",
  check,
});
