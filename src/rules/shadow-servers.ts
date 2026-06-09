import { registerRule } from "./index.js";
import type { Finding, RuleContext } from "./types.js";

// Minimal local interface to avoid circular import with scanner.ts.
// Compatible with ScanReport from scanner.ts (structural typing).
interface ScanReportLike {
  client: string;
  configPath: string;
  findings: Finding[];
  _serverNames?: string[];
}

// Per-server check: cannot detect cross-config duplicates at this level.
// Returns empty — cross-config detection happens in checkShadowServers().
function check(_ctx: RuleContext): Finding[] {
  return [];
}

registerRule({
  id: "shadow-servers",
  name: "Shadow Servers / Duplicate Names Across Configs",
  owasp: "MCP09",
  severity: "medium",
  check,
});

/**
 * Cross-config duplicate detection. Run AFTER all configs are scanned.
 * Groups server names across all reports and flags any name that appears
 * in 2 or more different config files.
 *
 * scanner.ts attaches `_serverNames: string[]` to each ScanReport before
 * calling this function, so we can identify server names without re-parsing.
 */
export function checkShadowServers(reports: ScanReportLike[]): Finding[] {
  const nameMap = new Map<string, Array<{ client: string; configPath: string }>>();

  for (const report of reports) {
    const serverNames = report._serverNames ?? [];
    for (const name of serverNames) {
      if (!nameMap.has(name)) {
        nameMap.set(name, []);
      }
      nameMap.get(name)!.push({ client: report.client, configPath: report.configPath });
    }
  }

  const findings: Finding[] = [];

  for (const [serverName, locations] of nameMap.entries()) {
    if (locations.length < 2) continue;

    const allLocations = locations
      .map((l) => `${l.client} (${l.configPath})`)
      .join(", ");

    for (const loc of locations) {
      findings.push({
        ruleId: "shadow-servers",
        severity: "medium",
        owasp: "MCP09",
        title: "Duplicate server name across multiple configs (shadow server risk)",
        description: `Server name "${serverName}" is defined in multiple config files: ${allLocations}. A malicious config could shadow a legitimate server, causing the wrong server to handle requests.`,
        remediation:
          `Rename one of the duplicate servers to a unique name (e.g., "${serverName}-cursor" or "${serverName}-vscode") to avoid ambiguity.`,
        client: loc.client,
        configPath: loc.configPath,
        serverName,
        evidence: `Defined in: ${allLocations}`,
      });
    }
  }

  return findings;
}
