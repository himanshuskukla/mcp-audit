import type { Finding } from "../rules/types.js";

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface ServerInfo {
  name?: string;
  version?: string;
  capabilities?: Record<string, unknown>;
  tools: McpTool[];
}

export interface LiveScanResult {
  serverName: string;
  client: string;
  configPath: string;
  connected: boolean;
  error?: string;
  toolCount: number;
  findings: Finding[];
}
