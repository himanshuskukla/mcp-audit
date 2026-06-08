import { describe, it, expect } from "vitest";
import { formatJson } from "../../src/output/json.js";
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
      title: "Hardcoded secret",
      description: "Found key in env",
      remediation: "Remove it",
      client: "Claude Desktop",
      configPath: "/tmp/test.json",
      serverName: "my-server",
      evidence: "API_KEY=sk-abc…",
    },
  ],
  summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
};

describe("JSON formatter", () => {
  it("produces valid JSON", () => {
    const output = formatJson([findingReport]);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it("includes version field", () => {
    const parsed = JSON.parse(formatJson([findingReport]));
    expect(parsed.version).toBe("0.1.0");
  });

  it("includes ISO timestamp", () => {
    const parsed = JSON.parse(formatJson([findingReport]));
    expect(parsed.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("includes summary with correct counts", () => {
    const parsed = JSON.parse(formatJson([findingReport]));
    expect(parsed.summary.configsScanned).toBe(1);
    expect(parsed.summary.totalFindings).toBe(1);
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.summary.high).toBe(0);
  });

  it("includes reports array with findings", () => {
    const parsed = JSON.parse(formatJson([findingReport]));
    expect(parsed.reports).toHaveLength(1);
    expect(parsed.reports[0].client).toBe("Claude Desktop");
    expect(parsed.reports[0].findings).toHaveLength(1);
  });

  it("handles empty reports array", () => {
    const parsed = JSON.parse(formatJson([]));
    expect(parsed.summary.configsScanned).toBe(0);
    expect(parsed.summary.totalFindings).toBe(0);
    expect(parsed.reports).toHaveLength(0);
  });

  it("aggregates counts across multiple reports", () => {
    const secondReport: ScanReport = {
      client: "Cursor",
      configPath: "/tmp/cursor.json",
      serverCount: 1,
      findings: [
        {
          ruleId: "missing-tls",
          severity: "high",
          owasp: "MCP06",
          title: "Missing TLS",
          description: "HTTP used",
          remediation: "Use HTTPS",
          client: "Cursor",
          configPath: "/tmp/cursor.json",
          serverName: "remote-server",
        },
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    };
    const parsed = JSON.parse(formatJson([findingReport, secondReport]));
    expect(parsed.summary.configsScanned).toBe(2);
    expect(parsed.summary.totalFindings).toBe(2);
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.summary.high).toBe(1);
  });
});
