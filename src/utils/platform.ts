import { homedir, platform } from "node:os";
import { resolve } from "node:path";

export type Platform = "darwin" | "linux" | "win32";

export function getPlatform(): Platform {
  const p = platform();
  if (p === "darwin" || p === "linux" || p === "win32") return p;
  return "linux";
}

export function getHomedir(): string {
  return homedir();
}

export function expandHome(filepath: string): string {
  if (filepath.startsWith("~/") || filepath === "~") {
    return resolve(homedir(), filepath.slice(2));
  }
  return filepath;
}

export function expandEnvVars(filepath: string): string {
  return filepath.replace(/%([^%]+)%/g, (_, key) => process.env[key] ?? "");
}
