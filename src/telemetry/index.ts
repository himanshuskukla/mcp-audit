import type { ScanReport } from "../scanner.js";
import type { LiveScanResult } from "../live/types.js";
import type { TelemetryConfig } from "./config.js";
import { getConfigPath, readConfig, writeConfig, isTTY } from "./config.js";
import { promptForConsent } from "./prompt.js";
import { buildPayload, sendTelemetry } from "./sender.js";

interface ShareDecision {
  share: boolean;
  prompt: boolean;
}

export function shouldShare(opts: {
  shareFlag: boolean | undefined;
  config: TelemetryConfig | null;
  tty: boolean;
}): ShareDecision {
  if (opts.shareFlag === true) return { share: true, prompt: false };
  if (opts.shareFlag === false) return { share: false, prompt: false };
  if (opts.config !== null) return { share: opts.config.telemetry, prompt: false };
  if (opts.tty) return { share: false, prompt: true };
  return { share: false, prompt: false };
}

export async function handleTelemetry(
  reports: ScanReport[],
  liveResults: LiveScanResult[] | undefined,
  opts: { share: boolean | undefined },
): Promise<void> {
  try {
    const configPath = getConfigPath();
    const config = readConfig(configPath);
    const decision = shouldShare({
      shareFlag: opts.share,
      config,
      tty: isTTY(),
    });

    let doShare = decision.share;

    if (decision.prompt) {
      const consented = await promptForConsent(configPath);
      writeConfig(configPath, { telemetry: consented });
      doShare = consented;
    }

    if (opts.share === true && config?.telemetry !== true) {
      writeConfig(configPath, { telemetry: true });
    }
    if (opts.share === false && config?.telemetry !== false) {
      writeConfig(configPath, { telemetry: false });
    }

    if (doShare) {
      const payload = buildPayload(reports, liveResults);
      await sendTelemetry(payload);
    }
  } catch {
    // Silently swallow — telemetry must never affect the scan
  }
}
