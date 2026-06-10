import { spawn } from "node:child_process";
import type { McpServerEntry } from "../discovery/types.js";
import type { McpTool, ServerInfo } from "./types.js";

const DEFAULT_TIMEOUT_MS = 15_000;

interface ConnectSuccess {
  success: true;
  info: ServerInfo;
}

interface ConnectFailure {
  success: false;
  error: string;
}

type ConnectResult = ConnectSuccess | ConnectFailure;

/**
 * Connect to an MCP server and fetch its tool list.
 * Supports stdio (command + args) and HTTP (url) transports.
 * Never throws — returns { success: false, error } on failure.
 */
export async function connectAndFetchTools(
  server: McpServerEntry,
  serverName: string,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<ConnectResult> {
  if (server.url || server.serverUrl) {
    return connectHttp(server, serverName, timeoutMs);
  }
  if (server.command) {
    return connectStdio(server, serverName, timeoutMs);
  }
  return { success: false, error: "Server has no command or url configured" };
}

// ─── Stdio transport ──────────────────────────────────────────────────

async function connectStdio(
  server: McpServerEntry,
  serverName: string,
  timeoutMs: number,
): Promise<ConnectResult> {
  return new Promise<ConnectResult>((resolve) => {
    let settled = false;
    const settle = (result: ConnectResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    // Merge env: process.env as base, server.env as overrides
    const env = { ...process.env, ...(server.env ?? {}) };

    let child;
    try {
      child = spawn(server.command!, server.args ?? [], {
        stdio: ["pipe", "pipe", "pipe"],
        env,
      });
    } catch (err: any) {
      settle({ success: false, error: `Failed to spawn process: ${err.message}` });
      return;
    }

    // Timeout
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      settle({ success: false, error: `Timeout after ${timeoutMs / 1000}s` });
    }, timeoutMs);

    // Handle process errors (e.g., command not found)
    child.on("error", (err) => {
      clearTimeout(timer);
      settle({ success: false, error: `Process error: ${err.message}` });
    });

    // Handle process exit before we get data
    child.on("exit", (code) => {
      clearTimeout(timer);
      settle({ success: false, error: `Process exited with code ${code} before responding` });
    });

    // Line-based JSON-RPC reader
    let buffer = "";
    let phase: "init" | "tools" | "done" = "init";
    let serverInfo: Partial<ServerInfo> = { tools: [] };
    let nextId = 1;

    child.stdout!.on("data", (chunk: Buffer) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? ""; // Keep incomplete last line in buffer

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        let msg: any;
        try {
          msg = JSON.parse(trimmed);
        } catch {
          continue; // Skip non-JSON lines (log output, etc.)
        }

        if (phase === "init" && msg.id === 1 && msg.result) {
          // Initialize response received
          const result = msg.result;
          serverInfo.name = result.serverInfo?.name;
          serverInfo.version = result.serverInfo?.version;
          serverInfo.capabilities = result.capabilities ?? {};

          // Send initialized notification
          const notification = JSON.stringify({
            jsonrpc: "2.0",
            method: "notifications/initialized",
          });
          child.stdin!.write(notification + "\n");

          // Send tools/list request
          nextId++;
          const toolsReq = JSON.stringify({
            jsonrpc: "2.0",
            id: nextId,
            method: "tools/list",
            params: {},
          });
          child.stdin!.write(toolsReq + "\n");
          phase = "tools";
        } else if (phase === "tools" && msg.id === nextId && msg.result) {
          // Tools list response
          const tools: McpTool[] = (msg.result.tools ?? []).map((t: any) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          }));
          serverInfo.tools = tools;
          phase = "done";

          // Done — kill child and resolve
          clearTimeout(timer);
          child.kill("SIGTERM");
          settle({ success: true, info: serverInfo as ServerInfo });
        } else if (msg.error) {
          clearTimeout(timer);
          child.kill("SIGTERM");
          settle({
            success: false,
            error: `Server returned error: ${msg.error.message ?? JSON.stringify(msg.error)}`,
          });
        }
      }
    });

    // Ignore stderr (servers often log there)
    child.stderr!.on("data", () => {});

    // Send initialize request
    const initReq = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "mcp-audit", version: "0.1.4" },
      },
    });
    child.stdin!.write(initReq + "\n");
  });
}

// ─── HTTP transport ───────────────────────────────────────────────────

async function connectHttp(
  server: McpServerEntry,
  serverName: string,
  timeoutMs: number,
): Promise<ConnectResult> {
  const url = server.url ?? server.serverUrl!;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    // Send initialize
    const initRes = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "mcp-audit", version: "0.1.4" },
        },
      }),
      signal: controller.signal,
    });

    const initData: any = await initRes.json();
    if (initData.error) {
      clearTimeout(timer);
      return { success: false, error: `Server error: ${initData.error.message ?? JSON.stringify(initData.error)}` };
    }

    const serverInfo: Partial<ServerInfo> = {
      name: initData.result?.serverInfo?.name,
      version: initData.result?.serverInfo?.version,
      capabilities: initData.result?.capabilities ?? {},
      tools: [],
    };

    // Send initialized notification (fire and forget)
    fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }),
    }).catch(() => {});

    // Send tools/list
    const toolsRes = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    const toolsData: any = await toolsRes.json();
    if (toolsData.error) {
      return { success: false, error: `Server error on tools/list: ${toolsData.error.message ?? JSON.stringify(toolsData.error)}` };
    }

    serverInfo.tools = (toolsData.result?.tools ?? []).map((t: any) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    }));

    return { success: true, info: serverInfo as ServerInfo };
  } catch (err: any) {
    if (err.name === "AbortError") {
      return { success: false, error: `Timeout after ${timeoutMs / 1000}s` };
    }
    return { success: false, error: `HTTP error: ${err.message}` };
  }
}
