import { describe, it, expect } from "vitest";
import { formatTerminal, formatLiveTerminal } from "../../src/output/terminal.js";
import type { ScanReport } from "../../src/scanner.js";
import type { LiveScanResult } from "../../src/live/types.js";

const findingReport: ScanReport = {
  client: "Claude Desktop",
  configPath: "/tmp/test.json",
  serverCount: 1,
  findings: [
    {
      ruleId: "hardcoded-secrets",
      severity: "critical",
      owasp: "MCP01",
      title: "Hardcoded OpenAI API Key",
      description: "Found key in env",
      remediation: "Remove it",
      client: "Claude Desktop",
      configPath: "/tmp/test.json",
      serverName: "my-server",
      evidence: "env.API_KEY = sk-...",
    },
  ],
  summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
};

const cleanReport: ScanReport = {
  client: "Cursor",
  configPath: "/tmp/test.json",
  serverCount: 2,
  findings: [],
  summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
};

// A report with 0 servers AND 0 findings — should be hidden
const emptyReport: ScanReport = {
  client: "VS Code",
  configPath: "/tmp/vscode.json",
  serverCount: 0,
  findings: [],
  summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
};

describe("terminal formatter", () => {
  it("formats a report with findings", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("Claude Desktop");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("MCP01");
    expect(output).toContain("1 finding");
  });

  it("formats clean report (has servers, no findings)", () => {
    const output = formatTerminal([cleanReport], { format: "terminal", noColor: true });
    expect(output).toContain("Cursor");
    expect(output).toContain("0 findings");
  });

  it("includes evidence in output when present", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("sk-...");
  });

  it("includes remediation text", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("Remove it");
  });

  it("includes config path", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("/tmp/test.json");
  });

  it("includes server name", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("my-server");
  });

  it("formats multiple reports together", () => {
    const output = formatTerminal([findingReport, cleanReport], { format: "terminal", noColor: true });
    expect(output).toContain("Claude Desktop");
    expect(output).toContain("Cursor");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("0 findings");
  });

  it("shows all-clean footer when no findings", () => {
    const output = formatTerminal([cleanReport], { format: "terminal", noColor: true });
    expect(output).toContain("No security issues found");
  });

  it("shows total count in footer when findings present", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("1 total finding");
  });

  it("produces colored output by default (no noColor flag)", () => {
    const output = formatTerminal([findingReport], { format: "terminal" });
    // ANSI escape codes present when color is on
    expect(output).toContain("\x1b[");
  });

  it("produces no ANSI codes when noColor is true", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).not.toContain("\x1b[");
  });

  // Change 1: empty client hiding
  it("hides clients with 0 servers and 0 findings", () => {
    const output = formatTerminal([emptyReport], { format: "terminal", noColor: true });
    expect(output).not.toContain("VS Code");
  });

  it("still shows clients with 0 findings but servers present", () => {
    const output = formatTerminal([cleanReport], { format: "terminal", noColor: true });
    expect(output).toContain("Cursor");
  });

  it("does not hide empty client when included alongside a client with findings", () => {
    const output = formatTerminal([findingReport, emptyReport], { format: "terminal", noColor: true });
    expect(output).toContain("Claude Desktop");
    expect(output).not.toContain("VS Code");
  });

  // Change 2: summary table
  it("includes a summary table header", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("Findings Summary");
  });

  it("includes table column headers", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("Severity");
    expect(output).toContain("OWASP");
    expect(output).toContain("Client");
    expect(output).toContain("Server");
    expect(output).toContain("Issue");
  });

  it("includes finding data in the table", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("CRITICAL");
    expect(output).toContain("MCP01");
  });

  it("shows 'No security issues found' in table section when no findings", () => {
    const output = formatTerminal([cleanReport], { format: "terminal", noColor: true });
    // The table section should mention no findings
    expect(output).toContain("No security issues found");
  });

  it("includes live findings in summary table when liveResults passed", () => {
    const liveResult: LiveScanResult = {
      serverName: "live-server",
      client: "Claude Code",
      configPath: "/tmp/live.json",
      connected: true,
      toolCount: 3,
      findings: [
        {
          ruleId: "test-live",
          severity: "high",
          owasp: "MCP06",
          title: "Live Finding Title",
          description: "A live finding",
          remediation: "Fix it",
          client: "Claude Code",
          configPath: "/tmp/live.json",
          serverName: "live-server",
        },
      ],
    };
    const output = formatTerminal([cleanReport], { format: "terminal", noColor: true }, [liveResult]);
    expect(output).toContain("Live Finding Title");
    expect(output).toContain("HIGH");
  });

  // Change 3: security score
  it("includes Security Score line", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("Security Score:");
    expect(output).toContain("/100");
  });

  it("shows 100/100 for clean scan", () => {
    const output = formatTerminal([cleanReport], { format: "terminal", noColor: true });
    expect(output).toContain("100/100");
    expect(output).toContain("Excellent");
  });

  it("reduces score for CRITICAL finding", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    // 1 CRITICAL = -25 => score 75
    expect(output).toContain("75/100");
  });
});

// Change 4: live error message formatting
describe("formatLiveTerminal", () => {
  const makeResult = (connected: boolean, error?: string): LiveScanResult => ({
    serverName: "test-server",
    client: "Claude Desktop",
    configPath: "/tmp/test.json",
    connected,
    error,
    toolCount: 0,
    findings: [],
  });

  it("shows friendly message for process-exited error", () => {
    const result = makeResult(false, "Process exited with code 0 before responding");
    const output = formatLiveTerminal([result], { format: "terminal", noColor: true });
    expect(output).toContain("server exited before responding");
    expect(output).not.toContain("Process exited with code 0");
  });

  it("shows friendly message for invalid_token error", () => {
    const result = makeResult(false, 'Server error: "invalid_token"');
    const output = formatLiveTerminal([result], { format: "terminal", noColor: true });
    expect(output).toContain("authentication required");
    expect(output).toContain("invalid_token");
  });

  it("shows friendly message for connection refused", () => {
    const result = makeResult(false, "ECONNREFUSED 127.0.0.1:3000");
    const output = formatLiveTerminal([result], { format: "terminal", noColor: true });
    expect(output).toContain("server not running");
  });

  it("uses 'skipped' instead of 'failed to connect' in footer", () => {
    const result = makeResult(false, "some error");
    const output = formatLiveTerminal([result], { format: "terminal", noColor: true });
    expect(output).toContain("skipped");
    expect(output).not.toContain("failed to connect");
  });

  it("shows connected result normally", () => {
    const result: LiveScanResult = {
      serverName: "good-server",
      client: "Claude Desktop",
      configPath: "/tmp/test.json",
      connected: true,
      toolCount: 5,
      findings: [],
    };
    const output = formatLiveTerminal([result], { format: "terminal", noColor: true });
    expect(output).toContain("good-server");
    expect(output).toContain("Tools: 5");
    expect(output).toContain("No findings.");
  });
});
