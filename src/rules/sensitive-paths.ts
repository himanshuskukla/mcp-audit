import { homedir } from "node:os";
import { registerRule } from "./index.js";
import type { Finding, RuleContext } from "./types.js";

const SENSITIVE_PATH_SUFFIXES = [
  ".ssh",
  ".aws",
  ".gnupg",
  ".gpg",
  ".config/gcloud",
  ".kube",
  ".docker",
  ".npmrc",
  ".pypirc",
  ".gem/credentials",
  ".gitconfig",
  ".env",
  ".password-store",
];

function resolvePath(p: string): string {
  if (p.startsWith("~/")) {
    return homedir() + p.slice(1);
  }
  if (p === "~") {
    return homedir();
  }
  return p;
}

function isSensitivePath(arg: string): string | null {
  const resolved = resolvePath(arg);
  const home = homedir();

  for (const suffix of SENSITIVE_PATH_SUFFIXES) {
    const full = `${home}/${suffix}`;

    // Matches exactly or is a subdirectory/file within it
    if (resolved === full || resolved.startsWith(full + "/")) {
      return suffix;
    }
  }

  // Also catch any arg that has `.env` as a filename component (basename == .env or ends with /.env)
  const lastSegment = resolved.split("/").pop() ?? "";
  if (lastSegment === ".env") {
    return ".env";
  }

  return null;
}

function check(ctx: RuleContext): Finding[] {
  const { serverName, server, config } = ctx;
  const args = server.args ?? [];
  const findings: Finding[] = [];

  for (const arg of args) {
    const matched = isSensitivePath(arg);
    if (matched) {
      findings.push({
        ruleId: "sensitive-paths",
        severity: "high",
        owasp: "MCP02",
        title: "Sensitive credential path exposed as server argument",
        description: `Server "${serverName}" passes a sensitive path ("${arg}") as an argument. This may expose credentials, keys, or configuration secrets to the MCP server process.`,
        remediation:
          "Do not pass credential directories or files as arguments to MCP servers. Use environment variables with minimal scope or a secrets manager.",
        client: config.client,
        configPath: config.configPath,
        serverName,
        evidence: `arg=${arg}`,
      });
    }
  }

  return findings;
}

registerRule({
  id: "sensitive-paths",
  name: "Sensitive Path Exposure",
  owasp: "MCP02",
  severity: "high",
  check,
});
