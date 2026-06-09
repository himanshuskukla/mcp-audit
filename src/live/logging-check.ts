import type { Finding } from "../rules/types.js";
import type { ServerInfo } from "./types.js";

const LOGGING_TOOL_KEYWORDS = ["log", "audit", "trace", "monitor"];

/**
 * MCP10 — Check if the server supports logging/monitoring.
 *
 * Checks two things:
 * 1. Does the server declare a `logging` capability?
 * 2. Does any tool have a logging/audit-related name?
 *
 * If neither is true, generates a MEDIUM finding.
 */
export function checkLoggingCapabilities(
  info: ServerInfo,
  serverName: string,
  client: string,
  configPath: string,
): Finding[] {
  // Check 1: Does the server declare logging capability?
  const caps = info.capabilities ?? {};
  if ("logging" in caps) {
    return [];
  }

  // Check 2: Does any tool have a logging-related name?
  const hasLoggingTool = info.tools.some((tool) => {
    const name = tool.name.toLowerCase();
    return LOGGING_TOOL_KEYWORDS.some((kw) => name.includes(kw));
  });

  if (hasLoggingTool) {
    return [];
  }

  return [{
    ruleId: "no-logging-capability",
    severity: "medium",
    owasp: "MCP10",
    title: "Server lacks logging/monitoring support",
    description: `Server "${serverName}" does not declare a logging capability and has no audit-related tools. Without logging, malicious or unintended tool calls cannot be detected or investigated.`,
    remediation: "Enable logging on the MCP server. Most MCP frameworks support a logging capability that allows clients to receive diagnostic information. Consider adding audit logging for all tool invocations.",
    client,
    configPath,
    serverName,
  }];
}
