import type { Finding } from "../rules/types.js";
import type { McpTool } from "./types.js";

// ─── Pattern definitions ──────────────────────────────────────────────

const HIDDEN_INSTRUCTION_PATTERNS: RegExp[] = [
  /ignore previous instructions/i,
  /do not tell the user/i,
  /override system prompt/i,
  /you must always/i,
  /never reveal/i,
  /act as if/i,
  /pretend that/i,
  /\bdisregard\b/i,
  /forget everything/i,
];

const EXFILTRATION_PATTERNS: RegExp[] = [
  /\bsend to\b/i,
  /\bforward to\b/i,
  /\bupload to\b/i,
  /\bpost to\b/i,
  /\bwebhook\b/i,
  /\bcallback url\b/i,
  /\bexternal endpoint\b/i,
  /\bexfiltrate\b/i,
  /\bextract and send\b/i,
];

// URLs in descriptions that aren't documentation links
const URL_PATTERN = /https?:\/\/[^\s)>"]+/gi;
const DOC_URL_HOSTS = new Set([
  "docs.", "documentation.", "api.", "github.com", "developer.",
  "learn.", "wiki.", "spec.", "www.w3.org", "tools.ietf.org",
  "json-schema.org", "schema.org",
]);

const SCOPE_PATTERNS: RegExp[] = [
  /\baccess all files\b/i,
  /\bfull system access\b/i,
  /\badmin access\b/i,
  /\bread any\b/i,
  /\bwrite any\b/i,
  /\bdelete any\b/i,
  /\bmodify any\b/i,
  /\bunrestricted\b/i,
  /\bunlimited access\b/i,
  /\broot access\b/i,
  /\bsudo\b/i,
  /\belevated privileges\b/i,
];

// Suspicious Unicode code points
const SUSPICIOUS_CODEPOINTS = new Set([
  0x200B, // Zero-width space
  0x200C, // Zero-width non-joiner
  0x200D, // Zero-width joiner
  0xFEFF, // Zero-width no-break space (BOM)
  0x202E, // Right-to-left override
  0x202A, // Left-to-right embedding
  0x202B, // Right-to-left embedding
  0x202C, // Pop directional formatting
  0x202D, // Left-to-right override
  0x2060, // Word joiner
  0x2061, // Function application
  0x2062, // Invisible times
  0x2063, // Invisible separator
  0x2064, // Invisible plus
]);

const MAX_DESCRIPTION_LENGTH = 2000;

// ─── Analysis functions ───────────────────────────────────────────────

function checkHiddenInstructions(
  tool: McpTool,
  serverName: string,
  client: string,
  configPath: string,
): Finding[] {
  const desc = tool.description ?? "";
  if (!desc) return [];

  const findings: Finding[] = [];

  for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
    const match = desc.match(pattern);
    if (match) {
      findings.push({
        ruleId: "tool-poisoning-hidden-instructions",
        severity: "critical",
        owasp: "MCP03",
        title: "Hidden instruction in tool description",
        description: `Tool "${tool.name}" description contains "${match[0]}" — this may attempt to override agent behavior.`,
        remediation: "Review the tool description and remove any hidden instructions. Consider reporting this server to the MCP community.",
        client,
        configPath,
        serverName,
        evidence: truncateEvidence(desc, match.index!, match[0].length),
      });
      break; // One finding per check type per tool
    }
  }

  return findings;
}

function checkExfiltration(
  tool: McpTool,
  serverName: string,
  client: string,
  configPath: string,
): Finding[] {
  const desc = tool.description ?? "";
  if (!desc) return [];

  const findings: Finding[] = [];

  // Check phrase patterns
  for (const pattern of EXFILTRATION_PATTERNS) {
    const match = desc.match(pattern);
    if (match) {
      findings.push({
        ruleId: "tool-poisoning-exfiltration",
        severity: "high",
        owasp: "MCP03",
        title: "Data exfiltration hint in tool description",
        description: `Tool "${tool.name}" description contains "${match[0]}" — may indicate data is sent to external endpoints.`,
        remediation: "Verify that the tool does not send sensitive data to unauthorized external services. Review tool source code if available.",
        client,
        configPath,
        serverName,
        evidence: truncateEvidence(desc, match.index!, match[0].length),
      });
      return findings; // One finding is enough
    }
  }

  // Check for non-documentation URLs
  const urls = desc.match(URL_PATTERN);
  if (urls) {
    for (const url of urls) {
      try {
        const hostname = new URL(url).hostname;
        const isDocUrl = Array.from(DOC_URL_HOSTS).some(
          (prefix) => hostname.startsWith(prefix) || hostname === prefix,
        );
        if (!isDocUrl) {
          findings.push({
            ruleId: "tool-poisoning-exfiltration",
            severity: "high",
            owasp: "MCP03",
            title: "Suspicious URL in tool description",
            description: `Tool "${tool.name}" description contains URL "${url}" — may be used for data exfiltration.`,
            remediation: "Verify the URL is legitimate and not used to exfiltrate data. Remove if unnecessary.",
            client,
            configPath,
            serverName,
            evidence: url,
          });
          return findings;
        }
      } catch {
        // Invalid URL, skip
      }
    }
  }

  return findings;
}

function checkExcessiveScope(
  tool: McpTool,
  serverName: string,
  client: string,
  configPath: string,
): Finding[] {
  const desc = tool.description ?? "";
  if (!desc) return [];

  for (const pattern of SCOPE_PATTERNS) {
    const match = desc.match(pattern);
    if (match) {
      return [{
        ruleId: "tool-poisoning-scope",
        severity: "medium",
        owasp: "MCP03",
        title: "Excessive scope claim in tool description",
        description: `Tool "${tool.name}" claims "${match[0]}" — legitimate tools rarely need such broad access.`,
        remediation: "Apply the principle of least privilege. Tools should request only the permissions they need.",
        client,
        configPath,
        serverName,
        evidence: truncateEvidence(desc, match.index!, match[0].length),
      }];
    }
  }

  return [];
}

function checkSuspiciousUnicode(
  tool: McpTool,
  serverName: string,
  client: string,
  configPath: string,
): Finding[] {
  const desc = tool.description ?? "";
  if (!desc) return [];

  const suspiciousChars: string[] = [];

  for (let i = 0; i < desc.length; i++) {
    const cp = desc.codePointAt(i)!;

    if (SUSPICIOUS_CODEPOINTS.has(cp)) {
      suspiciousChars.push(`U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
    }

    // Skip surrogate pair second half
    if (cp > 0xFFFF) i++;
  }

  if (suspiciousChars.length > 0) {
    return [{
      ruleId: "tool-poisoning-unicode",
      severity: "high",
      owasp: "MCP03",
      title: "Suspicious Unicode characters in tool description",
      description: `Tool "${tool.name}" description contains hidden Unicode characters (${suspiciousChars.join(", ")}) that could confuse LLMs.`,
      remediation: "Remove invisible or directional Unicode characters from tool descriptions. These can be used to hide malicious instructions.",
      client,
      configPath,
      serverName,
      evidence: `Found ${suspiciousChars.length} suspicious character(s): ${suspiciousChars.join(", ")}`,
    }];
  }

  return [];
}

function checkDescriptionLength(
  tool: McpTool,
  serverName: string,
  client: string,
  configPath: string,
): Finding[] {
  const desc = tool.description ?? "";
  if (desc.length > MAX_DESCRIPTION_LENGTH) {
    return [{
      ruleId: "tool-poisoning-length",
      severity: "low",
      owasp: "MCP03",
      title: "Excessively long tool description",
      description: `Tool "${tool.name}" has a ${desc.length}-character description (threshold: ${MAX_DESCRIPTION_LENGTH}). Long descriptions may hide instructions in verbosity.`,
      remediation: "Review the full description for hidden instructions. Legitimate tools typically have concise descriptions under 500 characters.",
      client,
      configPath,
      serverName,
      evidence: `Description length: ${desc.length} characters`,
    }];
  }

  return [];
}

// ─── Helpers ──────────────────────────────────────────────────────────

function truncateEvidence(text: string, matchStart: number, matchLength: number): string {
  const contextBefore = 30;
  const contextAfter = 30;
  const start = Math.max(0, matchStart - contextBefore);
  const end = Math.min(text.length, matchStart + matchLength + contextAfter);
  let snippet = text.slice(start, end);
  if (start > 0) snippet = "..." + snippet;
  if (end < text.length) snippet = snippet + "...";
  return snippet;
}

// ─── Public API ───────────────────────────────────────────────────────

export function analyzeToolsForPoisoning(
  tools: McpTool[],
  serverName: string,
  client: string,
  configPath: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const tool of tools) {
    findings.push(...checkHiddenInstructions(tool, serverName, client, configPath));
    findings.push(...checkExfiltration(tool, serverName, client, configPath));
    findings.push(...checkExcessiveScope(tool, serverName, client, configPath));
    findings.push(...checkSuspiciousUnicode(tool, serverName, client, configPath));
    findings.push(...checkDescriptionLength(tool, serverName, client, configPath));
  }

  return findings;
}
