import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { readConfig, writeConfig, getConfigPath } from "../../src/telemetry/config.js";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("telemetry config", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = join(tmpdir(), `mcp-audit-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("returns null when config does not exist", () => {
    const result = readConfig(join(testDir, "nonexistent", "config.json"));
    expect(result).toBeNull();
  });

  it("reads telemetry: true from config", () => {
    const configPath = join(testDir, "config.json");
    writeFileSync(configPath, JSON.stringify({ telemetry: true }));
    const result = readConfig(configPath);
    expect(result).toEqual({ telemetry: true });
  });

  it("reads telemetry: false from config", () => {
    const configPath = join(testDir, "config.json");
    writeFileSync(configPath, JSON.stringify({ telemetry: false }));
    const result = readConfig(configPath);
    expect(result).toEqual({ telemetry: false });
  });

  it("returns null for malformed JSON", () => {
    const configPath = join(testDir, "config.json");
    writeFileSync(configPath, "not json{{{");
    const result = readConfig(configPath);
    expect(result).toBeNull();
  });

  it("writes config and creates parent directories", () => {
    const configPath = join(testDir, "nested", "deep", "config.json");
    writeConfig(configPath, { telemetry: true });
    const result = readConfig(configPath);
    expect(result).toEqual({ telemetry: true });
  });

  it("overwrites existing config", () => {
    const configPath = join(testDir, "config.json");
    writeConfig(configPath, { telemetry: true });
    writeConfig(configPath, { telemetry: false });
    const result = readConfig(configPath);
    expect(result).toEqual({ telemetry: false });
  });

  it("getConfigPath returns XDG path on darwin/linux", () => {
    const path = getConfigPath("darwin");
    expect(path).toContain(".config/mcp-audit/config.json");
  });
});
