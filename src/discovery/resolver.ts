import { existsSync } from "node:fs";
import { getPlatform, expandHome } from "../utils/platform.js";
import type { ClientDefinition, McpClientConfig } from "./types.js";
import { parseConfigFile } from "./parser.js";

const CLIENT_DEFINITIONS: ClientDefinition[] = [
  {
    name: "Claude Desktop",
    configPaths: {
      darwin: ["~/Library/Application Support/Claude/claude_desktop_config.json"],
      linux: ["~/.config/Claude/claude_desktop_config.json"],
      win32: ["%APPDATA%\\Claude\\claude_desktop_config.json"],
    },
    serverKey: "mcpServers",
  },
  {
    name: "Claude Code",
    configPaths: {
      darwin: ["~/.claude.json"],
      linux: ["~/.claude.json"],
      win32: ["%USERPROFILE%\\.claude.json"],
    },
    serverKey: "mcpServers",
  },
  {
    name: "Cursor",
    configPaths: {
      darwin: ["~/.cursor/mcp.json", ".cursor/mcp.json"],
      linux: ["~/.cursor/mcp.json", ".cursor/mcp.json"],
      win32: ["%USERPROFILE%\\.cursor\\mcp.json", ".cursor\\mcp.json"],
    },
    serverKey: "mcpServers",
  },
  {
    name: "VS Code",
    configPaths: {
      darwin: ["~/Library/Application Support/Code/User/mcp.json"],
      linux: ["~/.config/Code/User/mcp.json"],
      win32: ["%APPDATA%\\Code\\User\\mcp.json"],
    },
    serverKey: "servers",
  },
  {
    name: "Windsurf",
    configPaths: {
      darwin: ["~/.codeium/windsurf/mcp_config.json"],
      linux: ["~/.codeium/windsurf/mcp_config.json"],
      win32: ["%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json"],
    },
    serverKey: "mcpServers",
  },
  {
    name: "Gemini CLI",
    configPaths: {
      darwin: ["~/.gemini/settings.json", ".gemini/settings.json"],
      linux: ["~/.gemini/settings.json", ".gemini/settings.json"],
      win32: ["%USERPROFILE%\\.gemini\\settings.json", ".gemini\\settings.json"],
    },
    serverKey: "mcpServers",
  },
  {
    name: "LM Studio",
    configPaths: {
      darwin: ["~/.lmstudio/mcp.json"],
      linux: ["~/.lmstudio/mcp.json"],
      win32: ["%USERPROFILE%\\.lmstudio\\mcp.json"],
    },
    serverKey: "mcpServers",
  },
  {
    name: "VS Code RooCode",
    configPaths: {
      darwin: [
        "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
      ],
      linux: [
        "~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
      ],
      win32: [
        "%APPDATA%\\Code\\User\\globalStorage\\rooveterinaryinc.roo-cline\\settings\\mcp_settings.json",
      ],
    },
    serverKey: "mcpServers",
  },
  {
    name: "VS Code Augment",
    configPaths: {
      darwin: [
        "~/Library/Application Support/Code/User/globalStorage/augment.vscode-augment/augment-global-state/mcpServers.json",
      ],
      linux: [
        "~/.config/Code/User/globalStorage/augment.vscode-augment/augment-global-state/mcpServers.json",
      ],
      win32: [
        "%APPDATA%\\Code\\User\\globalStorage\\augment.vscode-augment\\augment-global-state\\mcpServers.json",
      ],
    },
    serverKey: "mcpServers",
  },
  {
    name: "Zed",
    configPaths: {
      darwin: ["~/.config/zed/settings.json"],
      linux: ["~/.config/zed/settings.json"],
    },
    serverKey: "context_servers",
  },
  {
    name: "Amazon Q Developer",
    configPaths: {
      darwin: ["~/Library/Application Support/amazon-q/mcp.json"],
      linux: ["~/.config/amazon-q/mcp.json"],
      win32: ["%APPDATA%\\amazon-q\\mcp.json"],
    },
    serverKey: "mcpServers",
  },
  {
    name: "Cline VS Code",
    configPaths: {
      darwin: [
        "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
      ],
      linux: [
        "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
      ],
      win32: [
        "%APPDATA%\\Code\\User\\globalStorage\\saoudrizwan.claude-dev\\settings\\cline_mcp_settings.json",
      ],
    },
    serverKey: "mcpServers",
  },
];

export function getClientDefinitions(): ClientDefinition[] {
  return CLIENT_DEFINITIONS;
}

export function resolveConfigPaths(client: ClientDefinition): string[] {
  const platform = getPlatform();
  const rawPaths = client.configPaths[platform] ?? [];
  return rawPaths.map((p) => expandHome(p));
}

export function discoverExistingConfigs(): McpClientConfig[] {
  const results: McpClientConfig[] = [];

  for (const client of CLIENT_DEFINITIONS) {
    const paths = resolveConfigPaths(client);
    for (const configPath of paths) {
      if (existsSync(configPath)) {
        const config = parseConfigFile(configPath, client.name, client.serverKey);
        if (config !== null) {
          results.push(config);
        }
      }
    }
  }

  return results;
}
