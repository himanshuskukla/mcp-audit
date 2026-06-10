import { describe, it, expect } from "vitest";
import { shouldShare } from "../../src/telemetry/index.js";

describe("shouldShare", () => {
  it("returns true when share flag is true", () => {
    const result = shouldShare({ shareFlag: true, config: null, tty: false });
    expect(result).toEqual({ share: true, prompt: false });
  });

  it("returns false when share flag is false", () => {
    const result = shouldShare({ shareFlag: false, config: null, tty: true });
    expect(result).toEqual({ share: false, prompt: false });
  });

  it("returns config value when config exists (no flag)", () => {
    const result = shouldShare({ shareFlag: undefined, config: { telemetry: true }, tty: true });
    expect(result).toEqual({ share: true, prompt: false });
  });

  it("returns config false when config says no (no flag)", () => {
    const result = shouldShare({ shareFlag: undefined, config: { telemetry: false }, tty: true });
    expect(result).toEqual({ share: false, prompt: false });
  });

  it("returns prompt when no config and TTY", () => {
    const result = shouldShare({ shareFlag: undefined, config: null, tty: true });
    expect(result).toEqual({ share: false, prompt: true });
  });

  it("returns skip when no config and non-TTY", () => {
    const result = shouldShare({ shareFlag: undefined, config: null, tty: false });
    expect(result).toEqual({ share: false, prompt: false });
  });
});
