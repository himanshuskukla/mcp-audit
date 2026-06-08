import type { McpClientConfig } from "../discovery/types.js";
import type { Finding, Rule, RuleContext } from "./types.js";

const registry: Rule[] = [];

export function registerRule(rule: Rule): void {
  registry.push(rule);
}

export function getRegisteredRules(): Rule[] {
  return [...registry];
}

export function runRules(config: McpClientConfig): Finding[] {
  const findings: Finding[] = [];
  for (const [serverName, server] of Object.entries(config.servers)) {
    const ctx: RuleContext = { serverName, server, config };
    for (const rule of registry) {
      findings.push(...rule.check(ctx));
    }
  }
  return findings;
}
