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

/** Truncate a plain string (no ANSI) to maxLen, appending "…" if cut. */
function truncate(s: string, maxLen: number): string {
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen - 1) + "…";
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

// ---------------------------------------------------------------------------
// Security score
// ---------------------------------------------------------------------------

const SEVERITY_DEDUCTIONS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 2,
  info: 0,
};

export interface SecurityScore {
  score: number;
  grade: string;
  label: string;
}

/** Calculate a 0–100 security score from an array of findings. Exported for testing. */
export function calculateSecurityScore(findings: Finding[]): SecurityScore {
  let score = 100;
  for (const f of findings) {
    score -= SEVERITY_DEDUCTIONS[f.severity];
  }
  score = Math.max(0, score);

  let grade: string;
  let label: string;
  if (score >= 90) {
    grade = "A";
    label = "Excellent";
  } else if (score >= 75) {
    grade = "B";
    label = "Good";
  } else if (score >= 50) {
    grade = "C";
    label = "Needs Attention";
  } else if (score >= 25) {
    grade = "D";
    label = "Poor";
  } else {
    grade = "F";
    label = "Critical Risk";
  }

  return { score, grade, label };
}

// ---------------------------------------------------------------------------
// Summary table
// ---------------------------------------------------------------------------

/**
 * Build a compact summary table from all findings (static + live).
 * Uses box-drawing characters. Works with and without color.
 */
function formatSummaryTable(allFindings: Finding[], noColor: boolean): string {
  if (allFindings.length === 0) {
    return colorize("No security issues found.", COLORS.green, noColor);
  }

  // Sort by severity order
  const severityIndex: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  const sorted = [...allFindings].sort(
    (a, b) => severityIndex[a.severity] - severityIndex[b.severity],
  );

  // Column widths (plain-text)
  const COL_SEV = 8;    // "CRITICAL"
  const COL_OWASP = 5;  // "MCP01"
  const COL_CLIENT = 15;
  const COL_SERVER = 15;
  const COL_ISSUE = 40;

  const border = (left: string, mid: string, join: string, right: string) =>
    left +
    "─".repeat(COL_SEV + 2) +
    mid +
    "─".repeat(COL_OWASP + 2) +
    mid +
    "─".repeat(COL_CLIENT + 2) +
    mid +
    "─".repeat(COL_SERVER + 2) +
    mid +
    "─".repeat(COL_ISSUE + 2) +
    right;

  const cell = (s: string, width: number) => ` ${pad(truncate(s, width), width)} `;

  const lines: string[] = [];

  lines.push(colorize(border("┌", "┬", "┬", "┐"), COLORS.dim, noColor));

  // Header row
  const headerSev = colorize(pad("Severity", COL_SEV), COLORS.bold, noColor);
  const headerOwasp = colorize(pad("OWASP", COL_OWASP), COLORS.bold, noColor);
  const headerClient = colorize(pad("Client", COL_CLIENT), COLORS.bold, noColor);
  const headerServer = colorize(pad("Server", COL_SERVER), COLORS.bold, noColor);
  const headerIssue = colorize(pad("Issue", COL_ISSUE), COLORS.bold, noColor);
  const pipe = colorize("│", COLORS.dim, noColor);
  lines.push(
    `${pipe} ${headerSev} ${pipe} ${headerOwasp} ${pipe} ${headerClient} ${pipe} ${headerServer} ${pipe} ${headerIssue} ${pipe}`,
  );

  lines.push(colorize(border("├", "┼", "┼", "┤"), COLORS.dim, noColor));

  // Data rows
  for (const f of sorted) {
    const sevPlain = SEVERITY_LABELS[f.severity];
    const sevText = noColor
      ? pad(sevPlain, COL_SEV)
      : colorize(pad(sevPlain, COL_SEV), SEVERITY_COLORS[f.severity], noColor);

    const owaspText = pad(f.owasp, COL_OWASP);
    const clientText = pad(truncate(f.client, COL_CLIENT), COL_CLIENT);
    const serverText = pad(truncate(f.serverName, COL_SERVER), COL_SERVER);
    const issueText = pad(truncate(f.title, COL_ISSUE), COL_ISSUE);

    lines.push(
      `${pipe} ${sevText} ${pipe} ${owaspText} ${pipe} ${clientText} ${pipe} ${serverText} ${pipe} ${issueText} ${pipe}`,
    );
  }

  lines.push(colorize(border("└", "┴", "┴", "┘"), COLORS.dim, noColor));

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// formatTerminal
// ---------------------------------------------------------------------------

export function formatTerminal(reports: ScanReport[], opts: OutputOptions = { format: "terminal" }, liveResults?: LiveScanResult[]): string {
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
    // Change 1: skip clients with 0 servers AND 0 findings — pure noise
    if (report.serverCount === 0 && report.findings.length === 0) {
      continue;
    }

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

  // Change 2 & 3: summary table + security score
  // Collect all static findings for the table
  const allStaticFindings: Finding[] = reports.flatMap((r) => r.findings);
  const allLiveFindings: Finding[] = liveResults ? liveResults.flatMap((r) => r.findings) : [];
  const allFindings = [...allStaticFindings, ...allLiveFindings];

  lines.push("");
  lines.push(colorize("─".repeat(60), COLORS.dim, noColor));
  lines.push(colorize("Findings Summary", COLORS.bold, noColor));
  lines.push("");
  lines.push(formatSummaryTable(allFindings, noColor));

  // Security score
  lines.push("");
  const { score, grade, label } = calculateSecurityScore(allFindings);
  const scoreText = `${score}/100`;
  const gradeText = `${grade} — ${label}`;

  let scoreColor: string;
  if (score >= 90) {
    scoreColor = COLORS.green;
  } else if (score >= 75) {
    scoreColor = COLORS.cyan;
  } else if (score >= 50) {
    scoreColor = COLORS.yellow;
  } else if (score >= 25) {
    scoreColor = COLORS.red;
  } else {
    scoreColor = COLORS.brightRed + COLORS.bold;
  }

  lines.push(
    colorize("Security Score: ", COLORS.bold, noColor) +
    colorize(scoreText, scoreColor, noColor) +
    colorize(` (${gradeText})`, COLORS.dim, noColor),
  );

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// formatLiveTerminal  (Change 4: user-friendly failure messages)
// ---------------------------------------------------------------------------

/** Convert a raw MCP connection error into a user-friendly one-liner. */
function humanizeConnectionError(rawError: string): string {
  const lower = rawError.toLowerCase();

  // "Process exited with code 0 before responding" or similar exit messages
  if (lower.includes("exited") || lower.includes("process exit")) {
    return "Skipped — server exited before responding (may need initialization or auth)";
  }

  // Authentication / token errors
  if (lower.includes("invalid_token") || lower.includes("unauthorized") || lower.includes("401")) {
    const tokenMatch = rawError.match(/"([^"]+)"/);
    const hint = tokenMatch ? ` (${tokenMatch[1]})` : "";
    return `Skipped — authentication required${hint}`;
  }

  // Permission / forbidden
  if (lower.includes("forbidden") || lower.includes("403")) {
    return "Skipped — access forbidden (check permissions or credentials)";
  }

  // Connection refused / timeout
  if (lower.includes("econnrefused") || lower.includes("connection refused")) {
    return "Skipped — server not running (connection refused)";
  }
  if (lower.includes("etimedout") || lower.includes("timeout")) {
    return "Skipped — connection timed out (server may be slow to start)";
  }

  // Generic: just clean up the raw error slightly but don't hide it
  return `Skipped — ${rawError}`;
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
      const rawError = result.error ?? "unknown error";
      const friendlyMsg = humanizeConnectionError(rawError);
      lines.push(`    ${colorize(friendlyMsg, COLORS.yellow, noColor)}`);
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
    summaryParts.push(colorize(`${failedCount} skipped`, COLORS.yellow, noColor));
  }
  if (totalLiveFindings > 0) {
    summaryParts.push(colorize(`${totalLiveFindings} finding${totalLiveFindings !== 1 ? "s" : ""}`, COLORS.red, noColor));
  } else if (scannedCount > 0) {
    summaryParts.push(colorize("no findings", COLORS.green, noColor));
  }
  lines.push(`Live scan: ${summaryParts.join(", ")}.`);

  return lines.join("\n");
}
