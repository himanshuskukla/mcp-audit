import { describe, it, expect } from "vitest";
import { runRules } from "../../src/rules/index.js";
import type { McpClientConfig } from "../../src/discovery/types.js";

describe("runRules", () => {
  it("returns empty array for empty servers config", () => {
    const config: McpClientConfig = {
      client: "test-client",
      configPath: "/test/config.json",
      servers: {},
      raw: {},
    };
    const findings = runRules(config);
    expect(findings).toEqual([]);
  });
});
