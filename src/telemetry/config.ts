import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export interface TelemetryConfig {
  telemetry: boolean;
}

export function getConfigPath(platform: string = process.platform): string {
  const home = homedir();
  if (platform === "win32") {
    return join(home, ".mcp-audit.json");
  }
  return join(home, ".config", "mcp-audit", "config.json");
}

export function readConfig(configPath: string): TelemetryConfig | null {
  try {
    const raw = readFileSync(configPath, "utf-8");
    const parsed = JSON.parse(raw);
    if (typeof parsed.telemetry !== "boolean") return null;
    return { telemetry: parsed.telemetry };
  } catch {
    return null;
  }
}

export function writeConfig(configPath: string, config: TelemetryConfig): void {
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
}

export function isTTY(): boolean {
  return Boolean(process.stdin.isTTY);
}
