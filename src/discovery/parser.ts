import { readFileSync } from "node:fs";
import type { McpClientConfig, McpServerEntry } from "./types.js";

export function parseConfigFile(
  configPath: string,
  clientName: string,
  serverKey: string
): McpClientConfig | null {
  let content: string;
  try {
    content = readFileSync(configPath, "utf-8");
  } catch {
    return null;
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }

  const serversObj = (parsed[serverKey] ?? {}) as Record<string, McpServerEntry>;

  return {
    client: clientName,
    configPath,
    servers: serversObj,
    raw: parsed,
  };
}
