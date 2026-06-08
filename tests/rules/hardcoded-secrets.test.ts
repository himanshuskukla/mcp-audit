import { describe, it, expect } from "vitest";
import "../../src/rules/hardcoded-secrets.js";
import { runRules } from "../../src/rules/index.js";
import type { McpClientConfig } from "../../src/discovery/types.js";

function makeConfig(env: Record<string, string>): McpClientConfig {
  return {
    client: "test-client",
    configPath: "/test/config.json",
    servers: {
      myServer: {
        command: "node",
        args: ["server.js"],
        env,
      },
    },
    raw: {},
  };
}

describe("hardcoded-secrets rule", () => {
  it("detects API keys in env vars", () => {
    const config = makeConfig({
      OPENAI_KEY: "sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    });
    const findings = runRules(config).filter(
      (f) => f.ruleId === "hardcoded-secrets"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].owasp).toBe("MCP01");
    expect(findings[0].evidence).toContain("OPENAI_KEY=");
  });

  it("detects database URLs in env vars", () => {
    const config = makeConfig({
      DATABASE_URL:
        "postgres://admin:supersecretpassword@db.example.com:5432/mydb",
    });
    const findings = runRules(config).filter(
      (f) => f.ruleId === "hardcoded-secrets"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].evidence).toContain("DATABASE_URL=");
  });

  it("ignores safe environment variable names", () => {
    const config = makeConfig({
      NODE_ENV: "production",
      PORT: "3000",
      DEBUG: "true",
      LOG_LEVEL: "info",
      PATH: "/usr/local/bin:/usr/bin:/bin",
    });
    const findings = runRules(config).filter(
      (f) => f.ruleId === "hardcoded-secrets"
    );
    expect(findings).toEqual([]);
  });
});
