import type { McpClientConfig, McpServerEntry } from "../discovery/types.js";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type OwaspMcpCategory =
  | "MCP01"
  | "MCP02"
  | "MCP03"
  | "MCP05"
  | "MCP06"
  | "MCP07"
  | "MCP09";

export interface Finding {
  ruleId: string;
  severity: Severity;
  owasp: OwaspMcpCategory;
  title: string;
  description: string;
  remediation: string;
  client: string;
  configPath: string;
  serverName: string;
  evidence?: string;
}

export interface RuleContext {
  serverName: string;
  server: McpServerEntry;
  config: McpClientConfig;
}

export interface Rule {
  id: string;
  name: string;
  owasp: OwaspMcpCategory;
  severity: Severity;
  check: (ctx: RuleContext) => Finding[];
}
