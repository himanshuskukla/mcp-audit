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
import "./rules/docker-sandboxing.js";
import "./rules/sensitive-paths.js";
import "./rules/env-leakage.js";

// shadow-servers: imported for side-effect AND named export
import { checkShadowServers } from "./rules/shadow-servers.js";

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
    const report: ScanReport & { _serverNames: string[] } = {
      client: config.client,
      configPath: config.configPath,
      serverCount: Object.keys(config.servers).length,
      findings,
      summary: countBySeverity(findings),
      _serverNames: Object.keys(config.servers),
    };
    reports.push(report);
  }

  // Cross-config shadow server detection: runs after all configs are scanned
  const shadowFindings = checkShadowServers(reports);
  if (shadowFindings.length > 0) {
    // Append shadow findings to the first report as a synthetic entry,
    // or distribute them to the matching report by configPath
    for (const finding of shadowFindings) {
      const target = reports.find((r) => r.configPath === finding.configPath);
      if (target) {
        target.findings.push(finding);
        target.summary = countBySeverity(target.findings);
      } else if (reports.length > 0) {
        reports[0].findings.push(finding);
        reports[0].summary = countBySeverity(reports[0].findings);
      }
    }
  }

  return reports;
}
