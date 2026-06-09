import type { ScanReport } from "../scanner.js";
import type { Severity } from "../rules/types.js";

interface JsonOutput {
  version: string;
  timestamp: string;
  summary: {
    configsScanned: number;
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  reports: ScanReport[];
}

function sumBySeverity(reports: ScanReport[], sev: Severity): number {
  return reports.reduce((acc, r) => acc + r.summary[sev], 0);
}

export function formatJson(reports: ScanReport[]): string {
  const totalFindings = reports.reduce((acc, r) => acc + r.summary.total, 0);

  // Strip internal _serverNames field before serializing
  const cleanReports = reports.map(({ _serverNames, ...rest }: any) => rest);

  const output: JsonOutput = {
    version: "0.1.3",
    timestamp: new Date().toISOString(),
    summary: {
      configsScanned: reports.length,
      totalFindings,
      critical: sumBySeverity(reports, "critical"),
      high: sumBySeverity(reports, "high"),
      medium: sumBySeverity(reports, "medium"),
      low: sumBySeverity(reports, "low"),
      info: sumBySeverity(reports, "info"),
    },
    reports: cleanReports,
  };

  return JSON.stringify(output, null, 2);
}
