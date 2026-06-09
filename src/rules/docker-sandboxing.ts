import { registerRule } from "./index.js";
import type { Finding, RuleContext } from "./types.js";

function isDockerCommand(command: string | undefined): boolean {
  if (!command) return false;
  return command === "docker" || command.endsWith("/docker");
}

function check(ctx: RuleContext): Finding[] {
  const { serverName, server, config } = ctx;

  if (!isDockerCommand(server.command)) return [];

  const args = server.args ?? [];
  const argsStr = args.join(" ");
  const findings: Finding[] = [];

  // Check 1: --privileged flag → CRITICAL
  if (args.includes("--privileged")) {
    findings.push({
      ruleId: "docker-sandboxing",
      severity: "critical",
      owasp: "MCP02",
      title: "Docker container runs in privileged mode",
      description: `Server "${serverName}" runs Docker with --privileged, granting the container nearly all host capabilities and full access to the host device filesystem.`,
      remediation:
        "Remove --privileged from the Docker args. If the server needs specific capabilities, use --cap-add=<CAPABILITY> for only the ones required.",
      client: config.client,
      configPath: config.configPath,
      serverName,
      evidence: `--privileged found in args`,
    });
  }

  // Check 2: --network=host → HIGH
  if (args.some((a) => a === "--network=host" || a === "--net=host")) {
    findings.push({
      ruleId: "docker-sandboxing",
      severity: "high",
      owasp: "MCP02",
      title: "Docker container uses host network",
      description: `Server "${serverName}" runs Docker with --network=host, allowing the container to access all host network interfaces and bypass network isolation.`,
      remediation:
        "Add --network=none to the Docker args if the server does not need network access. If it does, create a dedicated Docker network with docker network create mcp-net and use --network=mcp-net.",
      client: config.client,
      configPath: config.configPath,
      serverName,
      evidence: `--network=host found in args`,
    });
  }

  // Check 3: dangerous volume mounts → HIGH
  // Look for -v /:/... or -v /home:/...
  const volumePattern = /^-v$/;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    // Handle both `-v /path:...` as a single arg and `-v` followed by value
    let volumeValue: string | null = null;
    if (arg.startsWith("-v=")) {
      volumeValue = arg.slice(3);
    } else if (arg.startsWith("--volume=")) {
      volumeValue = arg.slice(9);
    } else if ((arg === "-v" || arg === "--volume") && i + 1 < args.length) {
      volumeValue = args[i + 1];
    } else if (arg.startsWith("-v") && !volumePattern.test(arg)) {
      // e.g. -v/host/path:... (uncommon but handle)
      volumeValue = arg.slice(2);
    }

    if (volumeValue) {
      const hostPath = volumeValue.split(":")[0];
      if (hostPath === "/" || hostPath === "/home" || hostPath.startsWith("/home/")) {
        findings.push({
          ruleId: "docker-sandboxing",
          severity: "high",
          owasp: "MCP02",
          title: "Docker container mounts sensitive host path",
          description: `Server "${serverName}" mounts a sensitive host path ("${hostPath}") into the container, potentially exposing the entire filesystem or home directory.`,
          remediation:
            `Replace the volume mount with a scoped directory: -v /path/to/specific/dir:/data instead of mounting / or /home.`,
          client: config.client,
          configPath: config.configPath,
          serverName,
          evidence: `-v ${volumeValue}`,
        });
      }
    }
  }

  // Check 4: missing --read-only → MEDIUM
  if (!args.includes("--read-only")) {
    findings.push({
      ruleId: "docker-sandboxing",
      severity: "medium",
      owasp: "MCP02",
      title: "Docker container filesystem is not read-only",
      description: `Server "${serverName}" does not use --read-only, allowing the container process to write anywhere in the container filesystem.`,
      remediation:
        "Add --read-only to the Docker args. If the server needs to write temporary files, add --tmpfs /tmp to allow writes only to /tmp.",
      client: config.client,
      configPath: config.configPath,
      serverName,
      evidence: `--read-only not found in args`,
    });
  }

  // Check 5: missing --network=none (when no --network flag at all) → MEDIUM
  const hasNetworkFlag = args.some(
    (a) =>
      a.startsWith("--network") ||
      a.startsWith("--net=") ||
      a === "--net"
  );
  if (!hasNetworkFlag) {
    findings.push({
      ruleId: "docker-sandboxing",
      severity: "medium",
      owasp: "MCP02",
      title: "Docker container has no explicit network isolation",
      description: `Server "${serverName}" does not specify --network=none, meaning the container gets default bridge network access and can make outbound connections.`,
      remediation:
        "Add --network=none to the Docker args if the server does not need network access. If it does, create a dedicated Docker network with docker network create mcp-net and use --network=mcp-net.",
      client: config.client,
      configPath: config.configPath,
      serverName,
      evidence: `No --network flag found in args`,
    });
  }

  return findings;
}

registerRule({
  id: "docker-sandboxing",
  name: "Docker Without Sandboxing",
  owasp: "MCP02",
  severity: "high",
  check,
});
