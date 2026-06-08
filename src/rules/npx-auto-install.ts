import { registerRule } from "./index.js";
import type { Finding, RuleContext } from "./types.js";

function check(ctx: RuleContext): Finding[] {
  const { serverName, server, config } = ctx;

  if (server.command !== "npx") return [];

  const args = server.args ?? [];
  const hasAutoInstall = args.includes("-y") || args.includes("--yes");

  if (!hasAutoInstall) return [];

  return [
    {
      ruleId: "npx-auto-install",
      severity: "medium",
      owasp: "MCP06",
      title: "npx used with auto-install flag",
      description: `Server "${serverName}" uses "npx" with the "-y" or "--yes" flag, which automatically installs packages without confirmation. This can silently pull untrusted code.`,
      remediation:
        'Remove the "-y" / "--yes" flag from npx invocations. Pin package versions and pre-install dependencies explicitly.',
      client: config.client,
      configPath: config.configPath,
      serverName,
      evidence: `npx ${args.join(" ")}`,
    },
  ];
}

registerRule({
  id: "npx-auto-install",
  name: "npx Auto-Install Without Confirmation",
  owasp: "MCP06",
  severity: "medium",
  check,
});
