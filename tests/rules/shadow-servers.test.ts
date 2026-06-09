import { describe, it, expect } from "vitest";
import { checkShadowServers } from "../../src/rules/shadow-servers.js";

// Minimal report shape compatible with ScanReportLike used by checkShadowServers
interface TestReport {
  client: string;
  configPath: string;
  findings: never[];
  _serverNames: string[];
}

function makeReport(
  client: string,
  configPath: string,
  serverNames: string[]
): TestReport {
  return {
    client,
    configPath,
    findings: [],
    _serverNames: serverNames,
  };
}

describe("shadow-servers rule (checkShadowServers)", () => {
  it("detects same server name in two different configs", () => {
    const reports = [
      makeReport("claude-desktop", "/Users/alice/.../claude_desktop_config.json", [
        "filesystem",
        "github",
      ]),
      makeReport("vscode", "/Users/alice/.../settings.json", [
        "filesystem",
        "postgres",
      ]),
    ];

    const findings = checkShadowServers(reports);
    expect(findings.length).toBeGreaterThan(0);

    const shadowFinding = findings.find(
      (f) => f.serverName === "filesystem"
    );
    expect(shadowFinding).toBeDefined();
    expect(shadowFinding!.ruleId).toBe("shadow-servers");
    expect(shadowFinding!.severity).toBe("medium");
    expect(shadowFinding!.owasp).toBe("MCP09");
    expect(shadowFinding!.evidence).toContain("claude-desktop");
    expect(shadowFinding!.evidence).toContain("vscode");
  });

  it("generates one finding per config location for the duplicate server", () => {
    const reports = [
      makeReport("claude-desktop", "/config1.json", ["myServer"]),
      makeReport("vscode", "/config2.json", ["myServer"]),
    ];

    const findings = checkShadowServers(reports).filter(
      (f) => f.serverName === "myServer"
    );
    // One finding per config that contains the duplicate
    expect(findings).toHaveLength(2);
    const clients = findings.map((f) => f.client);
    expect(clients).toContain("claude-desktop");
    expect(clients).toContain("vscode");
  });

  it("no findings when all server names are unique", () => {
    const reports = [
      makeReport("claude-desktop", "/config1.json", ["filesystem", "github"]),
      makeReport("vscode", "/config2.json", ["postgres", "redis"]),
    ];

    const findings = checkShadowServers(reports);
    expect(findings).toHaveLength(0);
  });

  it("handles empty reports array", () => {
    const findings = checkShadowServers([]);
    expect(findings).toHaveLength(0);
  });

  it("no findings when only one config is present (no cross-config duplicates possible)", () => {
    const reports = [
      makeReport("claude-desktop", "/config1.json", ["serverA", "serverB", "serverC"]),
    ];
    const findings = checkShadowServers(reports);
    expect(findings).toHaveLength(0);
  });
});
