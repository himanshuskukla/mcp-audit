import { describe, it, expect } from "vitest";
import { expandHome, getPlatform, getHomedir } from "../../src/utils/platform.js";

describe("platform utilities", () => {
  it("expands ~ to home directory", () => {
    const result = expandHome("~/some/path");
    expect(result).not.toContain("~");
    expect(result).toMatch(/^\/.*some\/path$/);
  });

  it("leaves absolute paths unchanged", () => {
    expect(expandHome("/usr/local/bin")).toBe("/usr/local/bin");
  });

  it("detects current platform", () => {
    const platform = getPlatform();
    expect(["darwin", "linux", "win32"]).toContain(platform);
  });

  it("returns a valid home directory", () => {
    const home = getHomedir();
    expect(home.length).toBeGreaterThan(0);
    expect(home).not.toContain("~");
  });
});
