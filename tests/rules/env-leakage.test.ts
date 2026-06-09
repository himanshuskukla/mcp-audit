import { describe, it, expect } from "vitest";
import "../../src/rules/env-leakage.js";
import { runRules } from "../../src/rules/index.js";
import type { McpClientConfig, McpServerEntry } from "../../src/discovery/types.js";

function makeConfig(server: McpServerEntry): McpClientConfig {
  return {
    client: "test-client",
    configPath: "/test/config.json",
    servers: {
      myServer: server,
    },
    raw: {},
  };
}

describe("env-leakage rule", () => {
  it("flags stdio server with no env block (inherits full environment)", () => {
    const config = makeConfig({
      command: "node",
      args: ["dist/server.js"],
      // env is undefined — not set at all
    });
    const findings = runRules(config).filter(
      (f) => f.ruleId === "env-leakage"
    );
    expect(findings.length).toBeGreaterThan(0);
    const inheritFinding = findings.find((f) =>
      f.title.toLowerCase().includes("inherits full process environment")
    );
    expect(inheritFinding).toBeDefined();
    expect(inheritFinding!.severity).toBe("medium");
    expect(inheritFinding!.owasp).toBe("MCP01");
  });

  it("flags env block containing AWS_SECRET_ACCESS_KEY", () => {
    const config = makeConfig({
      command: "node",
      args: ["dist/server.js"],
      env: {
        NODE_ENV: "production",
        AWS_SECRET_ACCESS_KEY: "some-value",
      },
    });
    const findings = runRules(config).filter(
      (f) => f.ruleId === "env-leakage"
    );
    const sensitiveVarFinding = findings.find((f) =>
      f.evidence?.includes("AWS_SECRET_ACCESS_KEY")
    );
    expect(sensitiveVarFinding).toBeDefined();
    expect(sensitiveVarFinding!.severity).toBe("medium");
    expect(sensitiveVarFinding!.title).toContain("Sensitive variable");
  });

  it("flags multiple sensitive vars independently", () => {
    const config = makeConfig({
      command: "node",
      args: ["dist/server.js"],
      env: {
        GITHUB_TOKEN: "ghp_xxxx",
        OPENAI_API_KEY: "sk-xxxx",
        PORT: "3000",
      },
    });
    const findings = runRules(config).filter(
      (f) => f.ruleId === "env-leakage"
    );
    const sensitiveFindings = findings.filter((f) =>
      f.title.includes("Sensitive variable")
    );
    expect(sensitiveFindings).toHaveLength(2);
    const evidenceKeys = sensitiveFindings.map((f) => f.evidence ?? "");
    expect(evidenceKeys.some((e) => e.includes("GITHUB_TOKEN"))).toBe(true);
    expect(evidenceKeys.some((e) => e.includes("OPENAI_API_KEY"))).toBe(true);
  });

  it("passes server with explicit safe-only env block", () => {
    const config = makeConfig({
      command: "node",
      args: ["dist/server.js"],
      env: {
        NODE_ENV: "production",
        PORT: "3000",
        LOG_LEVEL: "info",
      },
    });
    const findings = runRules(config).filter(
      (f) => f.ruleId === "env-leakage"
    );
    expect(findings).toHaveLength(0);
  });

  it("passes empty env block (explicitly no inheritance, no sensitive vars)", () => {
    const config = makeConfig({
      command: "node",
      args: ["dist/server.js"],
      env: {},
    });
    const findings = runRules(config).filter(
      (f) => f.ruleId === "env-leakage"
    );
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag remote (URL-based) servers", () => {
    const config = makeConfig({
      url: "https://my-mcp-server.example.com",
      // no command field → not a stdio server
    });
    const findings = runRules(config).filter(
      (f) => f.ruleId === "env-leakage"
    );
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag serverUrl-based servers", () => {
    const config = makeConfig({
      serverUrl: "https://my-mcp-server.example.com",
    });
    const findings = runRules(config).filter(
      (f) => f.ruleId === "env-leakage"
    );
    expect(findings).toHaveLength(0);
  });
});
