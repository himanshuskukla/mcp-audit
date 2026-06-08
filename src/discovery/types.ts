export interface McpServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  serverUrl?: string;
}

export interface McpClientConfig {
  client: string;
  configPath: string;
  servers: Record<string, McpServerEntry>;
  raw: unknown;
}

export interface ClientDefinition {
  name: string;
  configPaths: {
    darwin?: string[];
    linux?: string[];
    win32?: string[];
  };
  serverKey: string;
}
