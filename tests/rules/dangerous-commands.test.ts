import { describe, it, expect } from "vitest";
import "../../src/rules/dangerous-commands.js";
import { runRules } from "../../src/rules/index.js";
import type { McpClientConfig } from "../../src/discovery/types.js";

function makeConfig(
  command: string,
  args: string[] = []
): McpClientConfig {
  return {
    client: "test-client",
    configPath: "/test/config.json",
    servers: {
      myServer: {
        command,
        args,
      },
    },
    raw: {},
  };
}

describe("dangerous-commands rule", () => {
  it("flags bash as a shell interpreter command", () => {
    const config = makeConfig("bash", ["-c", "echo hello"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "dangerous-commands"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].owasp).toBe("MCP05");
    expect(findings[0].evidence).toContain("bash");
  });

  it("flags arguments containing shell metacharacters", () => {
    // Simulating a dangerous config where an MCP server was launched with shell injection patterns
    const config = makeConfig("node", [
      "-e",
      "dangerous; rm -rf /tmp/foo",
    ]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "dangerous-commands"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.evidence?.includes("args="))).toBe(true);
  });

  it("passes safe commands without metacharacters", () => {
    const config = makeConfig("node", ["dist/server.js", "--port", "3000"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "dangerous-commands"
    );
    expect(findings).toEqual([]);
  });
});
