import { describe, it, expect } from "vitest";
import { checkLoggingCapabilities } from "../../src/live/logging-check.js";

describe("logging check (MCP10)", () => {
  it("flags server with no logging capabilities", () => {
    const info = { tools: [{ name: "do_stuff" }], capabilities: {} };
    const findings = checkLoggingCapabilities(info, "test-server", "Test", "/tmp/t.json");
    expect(findings).toHaveLength(1);
    expect(findings[0].owasp).toBe("MCP10");
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].ruleId).toBe("no-logging-capability");
  });

  it("flags server with undefined capabilities", () => {
    const info = { tools: [{ name: "do_stuff" }] };
    const findings = checkLoggingCapabilities(info as any, "test-server", "Test", "/tmp/t.json");
    expect(findings).toHaveLength(1);
    expect(findings[0].owasp).toBe("MCP10");
  });

  it("passes server with logging capability", () => {
    const info = { tools: [{ name: "do_stuff" }], capabilities: { logging: {} } };
    const findings = checkLoggingCapabilities(info, "test-server", "Test", "/tmp/t.json");
    expect(findings).toHaveLength(0);
  });

  it("passes server with logging capability set to object with config", () => {
    const info = { tools: [{ name: "do_stuff" }], capabilities: { logging: { level: "info" } } };
    const findings = checkLoggingCapabilities(info, "test-server", "Test", "/tmp/t.json");
    expect(findings).toHaveLength(0);
  });

  it("passes server with audit-related tool", () => {
    const info = { tools: [{ name: "get_audit_log" }], capabilities: {} };
    const findings = checkLoggingCapabilities(info, "test-server", "Test", "/tmp/t.json");
    expect(findings).toHaveLength(0);
  });

  it("passes server with log-related tool", () => {
    const info = { tools: [{ name: "view_logs" }], capabilities: {} };
    const findings = checkLoggingCapabilities(info, "test-server", "Test", "/tmp/t.json");
    expect(findings).toHaveLength(0);
  });

  it("passes server with trace-related tool", () => {
    const info = { tools: [{ name: "start_trace" }], capabilities: {} };
    const findings = checkLoggingCapabilities(info, "test-server", "Test", "/tmp/t.json");
    expect(findings).toHaveLength(0);
  });

  it("passes server with monitor-related tool", () => {
    const info = { tools: [{ name: "health_monitor" }], capabilities: {} };
    const findings = checkLoggingCapabilities(info, "test-server", "Test", "/tmp/t.json");
    expect(findings).toHaveLength(0);
  });

  it("is case-insensitive for tool name matching", () => {
    const info = { tools: [{ name: "GetAuditLog" }], capabilities: {} };
    const findings = checkLoggingCapabilities(info, "test-server", "Test", "/tmp/t.json");
    expect(findings).toHaveLength(0);
  });

  it("populates finding fields correctly", () => {
    const info = { tools: [{ name: "do_stuff" }], capabilities: {} };
    const findings = checkLoggingCapabilities(info, "my-server", "Claude Desktop", "/path/config.json");
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.serverName).toBe("my-server");
    expect(f.client).toBe("Claude Desktop");
    expect(f.configPath).toBe("/path/config.json");
  });

  it("flags server with no tools and no logging", () => {
    const info = { tools: [], capabilities: {} };
    const findings = checkLoggingCapabilities(info, "empty-server", "Test", "/tmp/t.json");
    expect(findings).toHaveLength(1);
    expect(findings[0].owasp).toBe("MCP10");
  });
});
