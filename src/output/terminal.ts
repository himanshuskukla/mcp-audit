import type { ScanReport } from "../scanner.js";
import type { Finding, Severity } from "../rules/types.js";
import type { OutputOptions } from "./types.js";
import type { LiveScanResult } from "../live/types.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

// ANSI color codes
const COLORS: Record<string, string> = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  brightRed: "\x1b[91m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  blue: "\x1b[34m",
  green: "\x1b[32m",
  gray: "\x1b[90m",
  white: "\x1b[37m",
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: COLORS.brightRed + COLORS.bold,
  high: COLORS.red,
  medium: COLORS.yellow,
  low: COLORS.cyan,
  info: COLORS.blue,
};

function colorize(text: string, color: string, noColor: boolean): string {
  if (noColor) return text;
  return `${color}${text}${COLORS.reset}`;
}

function formatSeverityLabel(severity: Severity, noColor: boolean): string {
  const label = SEVERITY_LABELS[severity];
  return colorize(label, SEVERITY_COLORS[severity], noColor);
}

function pad(s: string, width: number): string {
  return s.padEnd(width);
}

function formatFinding(finding: Finding, noColor: boolean, index: number): string {
  const lines: string[] = [];
  const severityLabel = formatSeverityLabel(finding.severity, noColor);
  const owaspTag = colorize(`[${finding.owasp}]`, COLORS.gray, noColor);
  const serverLabel = colorize(`server: ${finding.serverName}`, COLORS.dim, noColor);

  lines.push(`  ${index + 1}. ${severityLabel} ${owaspTag} ${finding.title}`);
  lines.push(`     ${serverLabel}`);
  lines.push(`     ${colorize("Description:", COLORS.bold, noColor)} ${finding.description}`);
  if (finding.evidence) {
    lines.push(`     ${colorize("Evidence:   ", COLORS.bold, noColor)} ${colorize(finding.evidence, COLORS.gray, noColor)}`);
  }
  lines.push(`     ${colorize("Remediation:", COLORS.bold, noColor)} ${finding.remediation}`);

  return lines.join("\n");
}

function formatSummaryLine(summary: ScanReport["summary"], noColor: boolean): string {
  const total = summary.total;
  const parts: string[] = [];

  for (const sev of SEVERITY_ORDER) {
    const count = summary[sev];
    if (count > 0) {
      parts.push(colorize(`${count} ${SEVERITY_LABELS[sev]}`, SEVERITY_COLORS[sev], noColor));
    }
  }

  if (total === 0) {
    return colorize("0 findings", COLORS.green, noColor);
  }

  const totalLabel = `${total} finding${total !== 1 ? "s" : ""}`;
  return `${colorize(totalLabel, COLORS.bold, noColor)} (${parts.join(", ")})`;
}

export function formatTerminal(reports: ScanReport[], opts: OutputOptions = { format: "terminal" }): string {
  const noColor = opts.noColor ?? false;
  const lines: string[] = [];

  const header = colorize("mcp-audit", COLORS.bold, noColor) +
    colorize(" — MCP Security Scanner", COLORS.dim, noColor);
  lines.push(header);
  lines.push(colorize("─".repeat(60), COLORS.dim, noColor));
  lines.push("");

  // Grand totals across all reports
  let grandTotal = 0;
  let grandCritical = 0;
  let grandHigh = 0;

  for (const report of reports) {
    grandTotal += report.summary.total;
    grandCritical += report.summary.critical;
    grandHigh += report.summary.high;

    const clientHeader = colorize(report.client, COLORS.bold, noColor) +
      colorize(` (${report.serverCount} server${report.serverCount !== 1 ? "s" : ""})`, COLORS.dim, noColor);
    const pathLabel = colorize(report.configPath, COLORS.gray, noColor);

    lines.push(clientHeader);
    lines.push(`  ${pathLabel}`);

    if (report.findings.length === 0) {
      lines.push(`  ${colorize("No findings — config looks clean.", COLORS.green, noColor)}`);
      lines.push(`  ${formatSummaryLine(report.summary, noColor)}`);
    } else {
      // Group findings by severity for display order
      const bySeverity = new Map<Severity, Finding[]>();
      for (const sev of SEVERITY_ORDER) bySeverity.set(sev, []);
      for (const f of report.findings) {
        bySeverity.get(f.severity)!.push(f);
      }

      let idx = 0;
      for (const sev of SEVERITY_ORDER) {
        const sevFindings = bySeverity.get(sev)!;
        for (const finding of sevFindings) {
          lines.push(formatFinding(finding, noColor, idx));
          idx++;
        }
      }
      lines.push("");
      lines.push(`  Summary: ${formatSummaryLine(report.summary, noColor)}`);
    }
    lines.push("");
  }

  // Footer with overall summary
  lines.push(colorize("─".repeat(60), COLORS.dim, noColor));
  if (grandTotal === 0) {
    lines.push(colorize("All configurations passed. No security issues found.", COLORS.green, noColor));
  } else {
    const overallLabel = colorize(`${grandTotal} total finding${grandTotal !== 1 ? "s" : ""}`, COLORS.bold, noColor);
    const critNote = grandCritical > 0
      ? colorize(` including ${grandCritical} CRITICAL`, COLORS.brightRed + COLORS.bold, noColor)
      : "";
    const highNote = grandHigh > 0 && grandCritical === 0
      ? colorize(` including ${grandHigh} HIGH`, COLORS.red, noColor)
      : "";
    lines.push(`${overallLabel}${critNote}${highNote} across ${reports.length} config${reports.length !== 1 ? "s" : ""}.`);
    lines.push(colorize("Run with --format json for machine-readable output.", COLORS.dim, noColor));
  }

  return lines.join("\n");
}

export function formatLiveTerminal(results: LiveScanResult[], opts: OutputOptions = { format: "terminal" }): string {
  const noColor = opts.noColor ?? false;
  const lines: string[] = [];

  lines.push("");
  const header = colorize("Live Scan Results", COLORS.bold, noColor) +
    colorize(" (--live)", COLORS.dim, noColor);
  lines.push(header);
  lines.push(colorize("─".repeat(60), COLORS.dim, noColor));
  lines.push("");

  if (results.length === 0) {
    lines.push(colorize("  No servers to scan.", COLORS.dim, noColor));
    return lines.join("\n");
  }

  let totalLiveFindings = 0;

  for (const result of results) {
    const serverLabel = colorize(`Server: ${result.serverName}`, COLORS.bold, noColor) +
      colorize(` (${result.client})`, COLORS.dim, noColor);
    lines.push(`  ${serverLabel}`);

    if (!result.connected) {
      const errorMsg = result.error ?? "unknown error";
      lines.push(`    ${colorize("Connected:", COLORS.dim, noColor)} ${colorize("failed", COLORS.red, noColor)} (${errorMsg})`);
      lines.push("");
      continue;
    }

    lines.push(`    ${colorize("Connected:", COLORS.dim, noColor)} ${colorize("yes", COLORS.green, noColor)} ${colorize("|", COLORS.dim, noColor)} ${colorize("Tools:", COLORS.dim, noColor)} ${result.toolCount}`);

    if (result.findings.length === 0) {
      lines.push(`    ${colorize("No findings.", COLORS.green, noColor)}`);
    } else {
      totalLiveFindings += result.findings.length;
      for (let i = 0; i < result.findings.length; i++) {
        const f = result.findings[i];
        const sevLabel = formatSeverityLabel(f.severity, noColor);
        const owaspTag = colorize(`[${f.owasp}]`, COLORS.gray, noColor);
        lines.push(`    ${i + 1}. ${sevLabel} ${owaspTag} ${f.title}`);
        if (f.evidence) {
          lines.push(`       ${colorize("Evidence:", COLORS.dim, noColor)} ${colorize(f.evidence, COLORS.gray, noColor)}`);
        }
        lines.push(`       ${colorize("Remediation:", COLORS.dim, noColor)} ${f.remediation}`);
      }
    }
    lines.push("");
  }

  // Footer
  lines.push(colorize("─".repeat(60), COLORS.dim, noColor));
  const scannedCount = results.filter((r) => r.connected).length;
  const failedCount = results.filter((r) => !r.connected).length;
  const summaryParts = [`${scannedCount} server${scannedCount !== 1 ? "s" : ""} scanned`];
  if (failedCount > 0) {
    summaryParts.push(colorize(`${failedCount} failed to connect`, COLORS.yellow, noColor));
  }
  if (totalLiveFindings > 0) {
    summaryParts.push(colorize(`${totalLiveFindings} finding${totalLiveFindings !== 1 ? "s" : ""}`, COLORS.red, noColor));
  } else if (scannedCount > 0) {
    summaryParts.push(colorize("no findings", COLORS.green, noColor));
  }
  lines.push(`Live scan: ${summaryParts.join(", ")}.`);

  return lines.join("\n");
}
