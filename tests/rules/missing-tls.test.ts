import { describe, it, expect } from "vitest";
import "../../src/rules/missing-tls.js";
import { runRules } from "../../src/rules/index.js";
import type { McpClientConfig } from "../../src/discovery/types.js";

function makeConfig(urlFields: Partial<{ url: string; serverUrl: string }>): McpClientConfig {
  return {
    client: "test-client",
    configPath: "/test/config.json",
    servers: {
      myServer: {
        ...urlFields,
      },
    },
    raw: {},
  };
}

describe("missing-tls rule", () => {
  it("flags HTTP url to a remote host", () => {
    const config = makeConfig({ url: "http://api.example.com/mcp" });
    const findings = runRules(config).filter((f) => f.ruleId === "missing-tls");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].owasp).toBe("MCP07");
    expect(findings[0].evidence).toContain("http://api.example.com");
  });

  it("flags HTTP serverUrl to a remote host", () => {
    const config = makeConfig({ serverUrl: "http://remote-server.io:8080/rpc" });
    const findings = runRules(config).filter((f) => f.ruleId === "missing-tls");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].evidence).toContain("serverUrl=");
  });

  it("passes HTTPS and localhost HTTP connections", () => {
    // HTTPS remote
    const configHttps = makeConfig({ url: "https://api.example.com/mcp" });
    const findingsHttps = runRules(configHttps).filter(
      (f) => f.ruleId === "missing-tls"
    );
    expect(findingsHttps).toEqual([]);

    // HTTP localhost
    const configLocalhost = makeConfig({ url: "http://localhost:3000/mcp" });
    const findingsLocalhost = runRules(configLocalhost).filter(
      (f) => f.ruleId === "missing-tls"
    );
    expect(findingsLocalhost).toEqual([]);

    // HTTP 127.0.0.1
    const configLoopback = makeConfig({ url: "http://127.0.0.1:3000/mcp" });
    const findingsLoopback = runRules(configLoopback).filter(
      (f) => f.ruleId === "missing-tls"
    );
    expect(findingsLoopback).toEqual([]);
  });
});
