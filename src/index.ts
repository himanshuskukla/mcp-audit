import { Command } from "commander";
import { scanAll, scanConfigFile } from "./scanner.js";
import { formatTerminal } from "./output/terminal.js";
import { formatJson } from "./output/json.js";
import { getClientDefinitions } from "./discovery/resolver.js";

const program = new Command()
  .name("mcp-audit")
  .description("Security scanner for MCP server configurations — npm audit for MCP")
  .version("0.1.0")
  .option("-f, --format <format>", "output format: terminal, json", "terminal")
  .option("-c, --config <path>", "scan a specific config file")
  .option("--client <name>", "client name when using --config (default: Custom)")
  .option("--no-color", "disable colored output")
  .option("--strict", "exit with code 1 on any finding")
  .action(async (options) => {
    let reports;
    if (options.config) {
      const clientName = options.client ?? "Custom";
      const report = scanConfigFile(options.config, clientName, "mcpServers");
      reports = report ? [report] : [];
    } else {
      reports = scanAll();
    }
    if (reports.length === 0) {
      console.log("No MCP configurations found. Run mcp-audit --help for options.");
      return;
    }
    if (options.format === "json") {
      console.log(formatJson(reports));
    } else {
      console.log(formatTerminal(reports, { format: "terminal", noColor: !options.color }));
    }
    if (options.strict) {
      const totalFindings = reports.reduce((s, r) => s + r.summary.total, 0);
      if (totalFindings > 0) process.exit(1);
    }
  });

program
  .command("clients")
  .description("List all supported MCP clients and their config paths")
  .action(() => {
    const clients = getClientDefinitions();
    console.log(`\nmcp-audit supports ${clients.length} MCP clients:\n`);
    for (const client of clients) {
      const paths = Object.entries(client.configPaths)
        .map(([os, p]) => `  ${os}: ${(p as string[]).join(", ")}`)
        .join("\n");
      console.log(`${client.name}\n${paths}\n`);
    }
  });

program.parse();
