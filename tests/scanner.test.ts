import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanConfigFile } from "../src/scanner.js";

const FIXTURES = join(import.meta.dirname, "fixtures/configs");

describe("scanner orchestrator", () => {
  it("scans a file and returns a report", () => {
    const report = scanConfigFile(
      join(FIXTURES, "claude-desktop-secrets.json"),
      "Claude Desktop",
      "mcpServers"
    );
    expect(report).not.toBeNull();
    expect(report!.client).toBe("Claude Desktop");
    expect(report!.findings.length).toBeGreaterThan(0);
    expect(report!.summary.total).toBeGreaterThan(0);
  });

  it("returns report with zero findings for clean config", () => {
    const report = scanConfigFile(
      join(FIXTURES, "claude-desktop-clean.json"),
      "Claude Desktop",
      "mcpServers"
    );
    expect(report).not.toBeNull();
    expect(report!.findings).toHaveLength(0);
    expect(report!.summary.total).toBe(0);
  });

  it("returns null for non-existent file", () => {
    const report = scanConfigFile("/nonexistent/path.json", "Claude Desktop", "mcpServers");
    expect(report).toBeNull();
  });

  it("summary counts match findings array length", () => {
    const report = scanConfigFile(
      join(FIXTURES, "claude-desktop-secrets.json"),
      "Claude Desktop",
      "mcpServers"
    );
    expect(report).not.toBeNull();
    const { summary, findings } = report!;
    const sumCounted =
      summary.critical + summary.high + summary.medium + summary.low + summary.info;
    expect(sumCounted).toBe(summary.total);
    expect(summary.total).toBe(findings.length);
  });

  it("report includes serverCount", () => {
    const report = scanConfigFile(
      join(FIXTURES, "claude-desktop-secrets.json"),
      "Claude Desktop",
      "mcpServers"
    );
    expect(report).not.toBeNull();
    expect(report!.serverCount).toBe(2);
  });
});
