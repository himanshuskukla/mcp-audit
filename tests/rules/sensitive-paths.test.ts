import { describe, it, expect } from "vitest";
import { homedir } from "node:os";
import "../../src/rules/sensitive-paths.js";
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

describe("sensitive-paths rule", () => {
  it("flags ~/.ssh in args (tilde form)", () => {
    const config = makeConfig(["--keys-dir", "~/.ssh"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "sensitive-paths"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].owasp).toBe("MCP02");
    expect(findings[0].evidence).toContain("~/.ssh");
  });

  it("flags ~/.ssh in args (absolute form)", () => {
    const sshPath = `${homedir()}/.ssh`;
    const config = makeConfig(["--keys-dir", sshPath]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "sensitive-paths"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].evidence).toContain(".ssh");
  });

  it("flags path containing .env file as a component", () => {
    const config = makeConfig(["--config", "/project/myapp/.env"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "sensitive-paths"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].evidence).toContain(".env");
  });

  it("flags ~/.aws in args", () => {
    const config = makeConfig(["--credentials", "~/.aws"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "sensitive-paths"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].evidence).toContain("~/.aws");
  });

  it("passes normal project directory path", () => {
    const config = makeConfig(["--workspace", "/Users/alice/projects/myapp"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "sensitive-paths"
    );
    expect(findings).toHaveLength(0);
  });

  it("passes safe args without sensitive paths", () => {
    const config = makeConfig(["--port", "3000", "--host", "localhost"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "sensitive-paths"
    );
    expect(findings).toHaveLength(0);
  });

  it("flags ~/.kube in args", () => {
    const config = makeConfig(["--kube-config", "~/.kube"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "sensitive-paths"
    );
    expect(findings.length).toBeGreaterThan(0);
  });
});
