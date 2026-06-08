import { describe, it, expect } from "vitest";
import { getClientDefinitions, resolveConfigPaths } from "../../src/discovery/resolver.js";

describe("config path resolver", () => {
  it("returns definitions for all supported clients", () => {
    const clients = getClientDefinitions();
    expect(clients.length).toBeGreaterThanOrEqual(12);
    const names = clients.map((c) => c.name);
    expect(names).toContain("Claude Desktop");
    expect(names).toContain("Claude Code");
    expect(names).toContain("Cursor");
    expect(names).toContain("VS Code");
    expect(names).toContain("Windsurf");
    expect(names).toContain("Gemini CLI");
  });

  it("resolves paths for current platform without ~", () => {
    const clients = getClientDefinitions();
    const paths = resolveConfigPaths(clients[0]);
    for (const p of paths) {
      expect(p).not.toContain("~");
    }
  });
});
