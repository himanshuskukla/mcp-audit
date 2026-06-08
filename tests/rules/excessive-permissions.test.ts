import { describe, it, expect } from "vitest";
import { homedir } from "node:os";
import "../../src/rules/excessive-permissions.js";
import { runRules } from "../../src/rules/index.js";
import type { McpClientConfig } from "../../src/discovery/types.js";

function makeConfig(args: string[]): McpClientConfig {
  return {
    client: "test-client",
    configPath: "/test/config.json",
    servers: {
      myServer: {
        command: "node",
        args,
      },
    },
    raw: {},
  };
}

describe("excessive-permissions rule", () => {
  it("flags the filesystem root path /", () => {
    const config = makeConfig(["--allow-path", "/"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "excessive-permissions"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].owasp).toBe("MCP02");
    expect(findings[0].evidence).toBe("arg=/");
  });

  it("flags the user home directory", () => {
    const home = homedir();
    const config = makeConfig(["--allow-path", home]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "excessive-permissions"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].evidence).toBe(`arg=${home}`);
  });

  it("passes scoped project paths that are not dangerous", () => {
    const config = makeConfig(["/Users/user/projects/myapp", "--port", "4000"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "excessive-permissions"
    );
    expect(findings).toEqual([]);
  });
});
