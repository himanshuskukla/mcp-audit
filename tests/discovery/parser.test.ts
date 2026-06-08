import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { parseConfigFile } from "../../src/discovery/parser.js";

const FIXTURES = join(import.meta.dirname, "../fixtures/configs");

describe("config parser", () => {
  it("parses Claude Desktop config with mcpServers key", () => {
    const result = parseConfigFile(
      join(FIXTURES, "claude-desktop-secrets.json"),
      "Claude Desktop",
      "mcpServers"
    );
    expect(result).not.toBeNull();
    expect(Object.keys(result!.servers)).toHaveLength(2);
    expect(result!.servers["my-server"].env?.API_KEY).toBe("sk-proj-abc123def456");
  });

  it("parses VS Code config with servers key", () => {
    const result = parseConfigFile(
      join(FIXTURES, "vscode-clean.json"),
      "VS Code",
      "servers"
    );
    expect(result).not.toBeNull();
    expect(Object.keys(result!.servers)).toHaveLength(1);
  });

  it("returns null for non-existent file", () => {
    const result = parseConfigFile("/tmp/nonexistent.json", "Test", "mcpServers");
    expect(result).toBeNull();
  });

  it("returns empty servers for missing key", () => {
    const result = parseConfigFile(
      join(FIXTURES, "claude-desktop-clean.json"),
      "Claude Desktop",
      "nonExistentKey"
    );
    expect(result).not.toBeNull();
    expect(Object.keys(result!.servers)).toHaveLength(0);
  });
});
