import { describe, it, expect } from "vitest";
import { buildPayload } from "../../src/telemetry/sender.js";
import type { ScanReport } from "../../src/scanner.js";
import type { LiveScanResult } from "../../src/live/types.js";

const report1: ScanReport = {
  client: "Claude Code",
  configPath: "/home/user/.claude.json",
  serverCount: 3,
  findings: [
    {
      ruleId: "hardcoded-secrets",
      severity: "critical",
      owasp: "MCP01",
      title: "Hardcoded secret",
      description: "desc",
      remediation: "fix",
      client: "Claude Code",
      configPath: "/home/user/.claude.json",
      serverName: "my-server",
      evidence: "API_KEY=sk-secret123",
    },
  ],
  summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
};

const report2: ScanReport = {
  client: "Cursor",
  configPath: "/home/user/.cursor/mcp.json",
  serverCount: 2,
  findings: [
    {
      ruleId: "npx-auto-install",
      severity: "medium",
      owasp: "MCP06",
      title: "npx auto-install",
      description: "desc",
      remediation: "fix",
      client: "Cursor",
      configPath: "/home/user/.cursor/mcp.json",
      serverName: "other-server",
    },
  ],
  summary: { total: 1, critical: 0, high: 0, medium: 1, low: 0, info: 0 },
};

describe("buildPayload", () => {
  it("aggregates serverCount across reports", () => {
    const payload = buildPayload([report1, report2]);
    expect(payload.serverCount).toBe(5);
  });

  it("deduplicates client names", () => {
    const payload = buildPayload([report1, report2]);
    expect(payload.clients).toEqual(["Claude Code", "Cursor"]);
  });

  it("includes client names from liveResults", () => {
    const liveResult: LiveScanResult = {
      serverName: "live-srv",
      client: "VS Code",
      configPath: "/tmp/vscode.json",
      connected: true,
      toolCount: 2,
      findings: [],
    };
    const payload = buildPayload([report1], [liveResult]);
    expect(payload.clients).toContain("VS Code");
    expect(payload.clients).toContain("Claude Code");
  });

  it("calculates score from combined findings", () => {
    const payload = buildPayload([report1, report2]);
    // 1 CRITICAL (-25) + 1 MEDIUM (-5) = 70
    expect(payload.score).toBe(70);
    expect(payload.grade).toBe("C");
  });

  it("builds findings map with only non-zero severities", () => {
    const payload = buildPayload([report1, report2]);
    expect(payload.findings["hardcoded-secrets"]).toEqual({ critical: 1 });
    expect(payload.findings["npx-auto-install"]).toEqual({ medium: 1 });
  });

  it("merges live findings into findings map", () => {
    const liveResult: LiveScanResult = {
      serverName: "live-srv",
      client: "Claude Code",
      configPath: "/tmp/live.json",
      connected: true,
      toolCount: 3,
      findings: [
        {
          ruleId: "tool-poisoning",
          severity: "critical",
          owasp: "MCP03",
          title: "Tool poisoning",
          description: "desc",
          remediation: "fix",
          client: "Claude Code",
          configPath: "/tmp/live.json",
          serverName: "live-srv",
        },
      ],
    };
    const payload = buildPayload([report1], [liveResult]);
    expect(payload.findings["tool-poisoning"]).toEqual({ critical: 1 });
    expect(payload.live).toBe(true);
    expect(payload.totalFindings).toBe(2);
  });

  it("sets live: false when no liveResults", () => {
    const payload = buildPayload([report1]);
    expect(payload.live).toBe(false);
  });

  it("excludes server names, paths, evidence, secrets from payload", () => {
    const payload = buildPayload([report1]);
    const json = JSON.stringify(payload);
    expect(json).not.toContain("my-server");
    expect(json).not.toContain("/home/user");
    expect(json).not.toContain("sk-secret123");
    expect(json).not.toContain("API_KEY");
  });

  it("includes OS, arch, nodeVersion", () => {
    const payload = buildPayload([report1]);
    expect(payload.os).toBe(process.platform);
    expect(payload.arch).toBe(process.arch);
    expect(typeof payload.nodeVersion).toBe("string");
  });

  it("populates rulesFired from findings", () => {
    const payload = buildPayload([report1, report2]);
    expect(payload.rulesFired).toContain("hardcoded-secrets");
    expect(payload.rulesFired).toContain("npx-auto-install");
    expect(payload.rulesFired).toHaveLength(2);
  });
});
