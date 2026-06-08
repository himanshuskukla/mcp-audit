import { parseConfigFile } from "./discovery/parser.js";
import { discoverExistingConfigs } from "./discovery/resolver.js";
import { runRules } from "./rules/index.js";
import type { Finding, Severity } from "./rules/types.js";

// Import all rules (side-effect: registers them)
import "./rules/hardcoded-secrets.js";
import "./rules/dangerous-commands.js";
import "./rules/missing-tls.js";
import "./rules/npx-auto-install.js";
import "./rules/excessive-permissions.js";

export interface ScanReport {
  client: string;
  configPath: string;
  serverCount: number;
  findings: Finding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

function countBySeverity(findings: Finding[]): ScanReport["summary"] {
  const counts = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    counts.total++;
    counts[f.severity]++;
  }
  return counts;
}

export function scanConfigFile(
  configPath: string,
  clientName: string,
  serverKey: string
): ScanReport | null {
  const config = parseConfigFile(configPath, clientName, serverKey);
  if (!config) return null;
  const findings = runRules(config);
  return {
    client: clientName,
    configPath,
    serverCount: Object.keys(config.servers).length,
    findings,
    summary: countBySeverity(findings),
  };
}

export function scanAll(): ScanReport[] {
  const discovered = discoverExistingConfigs();
  const reports: ScanReport[] = [];
  for (const config of discovered) {
    const findings = runRules(config);
    reports.push({
      client: config.client,
      configPath: config.configPath,
      serverCount: Object.keys(config.servers).length,
      findings,
      summary: countBySeverity(findings),
    });
  }
  return reports;
}
