import type { ScanReport } from "../scanner.js";
import type { LiveScanResult } from "../live/types.js";
import type { Severity } from "../rules/types.js";
import { calculateSecurityScore } from "../utils/scoring.js";

const TELEMETRY_ENDPOINT = "https://mcp-audit-telemetry.thehimanshushukla-com.workers.dev/v1/report";
const TIMEOUT_MS = 3_000;

export interface TelemetryPayload {
  v: string;
  ts: string;
  os: string;
  arch: string;
  nodeVersion: string;
  clients: string[];
  serverCount: number;
  score: number;
  grade: string;
  live: boolean;
  findings: Record<string, Partial<Record<Severity, number>>>;
  rulesFired: string[];
  totalFindings: number;
}

export function buildPayload(
  reports: ScanReport[],
  liveResults?: LiveScanResult[],
): TelemetryPayload {
  const allStaticFindings = reports.flatMap((r) => r.findings);
  const allLiveFindings = liveResults ? liveResults.flatMap((r) => r.findings) : [];
  const allFindings = [...allStaticFindings, ...allLiveFindings];

  const clientSet = new Set<string>();
  for (const r of reports) clientSet.add(r.client);
  if (liveResults) {
    for (const r of liveResults) clientSet.add(r.client);
  }

  const findingsMap: Record<string, Partial<Record<Severity, number>>> = {};
  for (const f of allFindings) {
    if (!findingsMap[f.ruleId]) findingsMap[f.ruleId] = {};
    const entry = findingsMap[f.ruleId];
    entry[f.severity] = (entry[f.severity] ?? 0) + 1;
  }

  const rulesFired = [...new Set(allFindings.map((f) => f.ruleId))];
  const { score, grade } = calculateSecurityScore(allFindings);

  return {
    v: "0.1.4",
    ts: new Date().toISOString(),
    os: process.platform,
    arch: process.arch,
    nodeVersion: process.versions.node,
    clients: [...clientSet].sort(),
    serverCount: reports.reduce((s, r) => s + r.serverCount, 0),
    score,
    grade,
    live: liveResults !== undefined,
    findings: findingsMap,
    rulesFired,
    totalFindings: allFindings.length,
  };
}

export async function sendTelemetry(payload: TelemetryPayload): Promise<void> {
  try {
    await fetch(TELEMETRY_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    // Silently swallow — telemetry must never affect scan
  }
}
