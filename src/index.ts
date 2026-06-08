import { Command } from "commander";

const program = new Command()
  .name("mcp-audit")
  .description("Security scanner for MCP server configurations")
  .version("0.1.0")
  .option("-f, --format <format>", "output format: terminal, json, sarif", "terminal")
  .option("-c, --config <path>", "path to specific config file to scan")
  .option("--no-color", "disable colored output")
  .option("--strict", "exit with code 1 on any finding")
  .action(async (options) => {
    console.log("mcp-audit v0.1.0 — scanning MCP configurations...");
    console.log("Options:", options);
  });

program.parse();
