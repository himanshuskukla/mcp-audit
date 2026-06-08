import { describe, it, expect } from "vitest";
import "../../src/rules/npx-auto-install.js";
import { runRules } from "../../src/rules/index.js";
import type { McpClientConfig } from "../../src/discovery/types.js";

function makeConfig(command: string, args: string[]): McpClientConfig {
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

describe("npx-auto-install rule", () => {
  it("flags npx with -y flag", () => {
    const config = makeConfig("npx", ["-y", "@some/mcp-server"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "npx-auto-install"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].owasp).toBe("MCP06");
    expect(findings[0].evidence).toContain("-y");
  });

  it("passes npx without auto-install flags", () => {
    const config = makeConfig("npx", ["@some/mcp-server@1.2.3"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "npx-auto-install"
    );
    expect(findings).toEqual([]);
  });
});
