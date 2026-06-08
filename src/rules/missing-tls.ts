import { registerRule } from "./index.js";
import type { Finding, RuleContext } from "./types.js";

function isInsecureUrl(value: string): boolean {
  if (!value.startsWith("http://")) return false;
  try {
    const { hostname } = new URL(value);
    // Allow localhost and loopback
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "::1"
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function check(ctx: RuleContext): Finding[] {
  const { serverName, server, config } = ctx;
  const findings: Finding[] = [];

  const urlFields: Array<{ field: string; value: string | undefined }> = [
    { field: "url", value: server.url },
    { field: "serverUrl", value: server.serverUrl },
  ];

  for (const { field, value } of urlFields) {
    if (value && isInsecureUrl(value)) {
      findings.push({
        ruleId: "missing-tls",
        severity: "high",
        owasp: "MCP07",
        title: "Server connection uses insecure HTTP (no TLS)",
        description: `Server "${serverName}" field "${field}" uses HTTP without TLS. Data in transit is unencrypted and vulnerable to interception.`,
        remediation:
          "Use HTTPS instead of HTTP for all non-localhost server connections to ensure data is encrypted in transit.",
        client: config.client,
        configPath: config.configPath,
        serverName,
        evidence: `${field}=${value}`,
      });
    }
  }

  return findings;
}

registerRule({
  id: "missing-tls",
  name: "Missing TLS on Server Connection",
  owasp: "MCP07",
  severity: "high",
  check,
});
