import { createInterface } from "node:readline";

const PROMPT_TEXT = `
────────────────────────────────────────────────────────────
Help improve MCP security for everyone

  Share anonymous scan results with the mcp-audit community?
  This helps us track ecosystem-wide security trends.

  Shared:     finding counts by rule/severity, client names, score, OS
  NOT shared: server names, file paths, env values, secrets, IP addresses
`;

export async function promptForConsent(configPath: string): Promise<boolean> {
  console.log(PROMPT_TEXT);

  const rl = createInterface({ input: process.stdin, output: process.stdout });

  return new Promise<boolean>((resolve) => {
    rl.question("  Share? [Y/n] ", (answer) => {
      rl.close();
      const trimmed = answer.trim().toLowerCase();
      const consented = trimmed === "" || trimmed === "y" || trimmed === "yes";

      if (consented) {
        console.log(`\n  Choice saved to ${configPath}`);
      } else {
        console.log(`\n  No problem. Choice saved to ${configPath}`);
      }
      console.log("  (change anytime with --share / --no-share)");
      console.log("────────────────────────────────────────────────────────────");

      resolve(consented);
    });
  });
}
