import { describe, it, expect } from "vitest";
import { formatTerminal } from "../../src/output/terminal.js";
import type { ScanReport } from "../../src/scanner.js";

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

describe("terminal formatter", () => {
  it("formats a report with findings", () => {
    const output = formatTerminal([findingReport], { format: "terminal", noColor: true });
    expect(output).toContain("Claude Desktop");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("MCP01");
    expect(output).toContain("1 finding");
  });

  it("formats clean report", () => {
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
});
