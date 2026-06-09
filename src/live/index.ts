import type { McpClientConfig } from "../discovery/types.js";
import type { LiveScanResult } from "./types.js";
import { connectAndFetchTools } from "./connector.js";
import { analyzeToolsForPoisoning } from "./tool-poisoning.js";
import { checkLoggingCapabilities } from "./logging-check.js";

/**
 * Run a live scan on a single MCP server:
 * 1. Connect and fetch tools
 * 2. Analyze tool descriptions for poisoning (MCP03)
 * 3. Check logging capabilities (MCP10)
 */
export async function liveScanServer(
  serverName: string,
  server: McpClientConfig["servers"][string],
  client: string,
  configPath: string,
): Promise<LiveScanResult> {
  const result = await connectAndFetchTools(server, serverName);

  if (!result.success) {
    return {
      serverName,
      client,
      configPath,
      connected: false,
      error: result.error,
      toolCount: 0,
      findings: [],
    };
  }

  const { info } = result;

  // Run live analysis rules
  const poisoningFindings = analyzeToolsForPoisoning(
    info.tools, serverName, client, configPath,
  );
  const loggingFindings = checkLoggingCapabilities(
    info, serverName, client, configPath,
  );

  return {
    serverName,
    client,
    configPath,
    connected: true,
    toolCount: info.tools.length,
    findings: [...poisoningFindings, ...loggingFindings],
  };
}

/**
 * Run live scans on all servers across all discovered configs.
 * Runs SEQUENTIALLY to avoid resource exhaustion.
 */
export async function liveScanAll(
  configs: McpClientConfig[],
): Promise<LiveScanResult[]> {
  const results: LiveScanResult[] = [];

  for (const config of configs) {
    for (const [serverName, server] of Object.entries(config.servers)) {
      const result = await liveScanServer(
        serverName, server, config.client, config.configPath,
      );
      results.push(result);
    }
  }

  return results;
}

export type { LiveScanResult } from "./types.js";
