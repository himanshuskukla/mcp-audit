import { describe, it, expect } from "vitest";
import "../../src/rules/docker-sandboxing.js";
import { runRules } from "../../src/rules/index.js";
import type { McpClientConfig } from "../../src/discovery/types.js";

function makeConfig(command: string, args: string[]): McpClientConfig {
  return {
    client: "test-client",
    configPath: "/test/config.json",
    servers: {
      dockerServer: {
        command,
        args,
      },
    },
    raw: {},
  };
}

describe("docker-sandboxing rule", () => {
  it("flags --privileged with CRITICAL severity", () => {
    const config = makeConfig("docker", [
      "run",
      "--privileged",
      "some-mcp-image",
    ]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "docker-sandboxing"
    );
    const privilegedFinding = findings.find((f) =>
      f.evidence?.includes("--privileged")
    );
    expect(privilegedFinding).toBeDefined();
    expect(privilegedFinding!.severity).toBe("critical");
    expect(privilegedFinding!.owasp).toBe("MCP02");
  });

  it("flags missing --read-only on a basic docker run", () => {
    const config = makeConfig("docker", [
      "run",
      "--network=none",
      "some-mcp-image",
    ]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "docker-sandboxing"
    );
    const readOnlyFinding = findings.find((f) =>
      f.title.toLowerCase().includes("read-only")
    );
    expect(readOnlyFinding).toBeDefined();
    expect(readOnlyFinding!.severity).toBe("medium");
  });

  it("flags dangerous volume mount -v /:/host", () => {
    const config = makeConfig("docker", [
      "run",
      "--network=none",
      "--read-only",
      "-v",
      "/:/host",
      "some-mcp-image",
    ]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "docker-sandboxing"
    );
    const volumeFinding = findings.find((f) =>
      f.title.toLowerCase().includes("sensitive host path")
    );
    expect(volumeFinding).toBeDefined();
    expect(volumeFinding!.severity).toBe("high");
    expect(volumeFinding!.evidence).toContain("/:/host");
  });

  it("passes well-secured docker with --read-only, --network=none, --cap-drop=ALL", () => {
    const config = makeConfig("docker", [
      "run",
      "--read-only",
      "--network=none",
      "--cap-drop=ALL",
      "some-mcp-image",
    ]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "docker-sandboxing"
    );
    // No critical or high findings; privileged/network/volume checks should all pass
    const criticalOrHigh = findings.filter(
      (f) => f.severity === "critical" || f.severity === "high"
    );
    expect(criticalOrHigh).toHaveLength(0);
    // --read-only and --network=none are present so medium checks pass too
    expect(findings).toHaveLength(0);
  });

  it("skips non-docker commands", () => {
    const config = makeConfig("node", ["dist/server.js"]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "docker-sandboxing"
    );
    expect(findings).toHaveLength(0);
  });

  it("flags --network=host with HIGH severity", () => {
    const config = makeConfig("docker", [
      "run",
      "--network=host",
      "--read-only",
      "some-mcp-image",
    ]);
    const findings = runRules(config).filter(
      (f) => f.ruleId === "docker-sandboxing"
    );
    const networkFinding = findings.find((f) =>
      f.evidence?.includes("--network=host")
    );
    expect(networkFinding).toBeDefined();
    expect(networkFinding!.severity).toBe("high");
  });
});
