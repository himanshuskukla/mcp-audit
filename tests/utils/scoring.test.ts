import { describe, it, expect } from "vitest";
import { calculateSecurityScore } from "../../src/utils/scoring.js";

// calculateSecurityScore unit tests
describe("calculateSecurityScore", () => {
  it("returns 100 for no findings", () => {
    const { score, grade, label } = calculateSecurityScore([]);
    expect(score).toBe(100);
    expect(grade).toBe("A");
    expect(label).toBe("Excellent");
  });

  it("deducts 25 per CRITICAL", () => {
    const findings = Array.from({ length: 3 }, () => ({
      ruleId: "x",
      severity: "critical" as const,
      owasp: "MCP01" as const,
      title: "T",
      description: "D",
      remediation: "R",
      client: "C",
      configPath: "/p",
      serverName: "s",
    }));
    const { score } = calculateSecurityScore(findings);
    expect(score).toBe(25); // 100 - 75
  });

  it("floors at 0", () => {
    const findings = Array.from({ length: 10 }, () => ({
      ruleId: "x",
      severity: "critical" as const,
      owasp: "MCP01" as const,
      title: "T",
      description: "D",
      remediation: "R",
      client: "C",
      configPath: "/p",
      serverName: "s",
    }));
    const { score, grade } = calculateSecurityScore(findings);
    expect(score).toBe(0);
    expect(grade).toBe("F");
  });

  it("grades correctly across boundaries", () => {
    const make = (severity: "critical" | "high" | "medium" | "low", n: number) =>
      Array.from({ length: n }, () => ({
        ruleId: "x", severity, owasp: "MCP01" as const,
        title: "T", description: "D", remediation: "R",
        client: "C", configPath: "/p", serverName: "s",
      }));

    expect(calculateSecurityScore(make("medium", 2)).grade).toBe("A"); // 100 - 10 = 90 => A
    expect(calculateSecurityScore(make("medium", 5)).grade).toBe("B"); // 100 - 25 = 75 => B
    // 100 - 4*15 = 40 => D
    expect(calculateSecurityScore(make("high", 4)).score).toBe(40);
    expect(calculateSecurityScore(make("high", 4)).grade).toBe("D");
    expect(calculateSecurityScore(make("critical", 4)).grade).toBe("F"); // 0
  });

  it("INFO findings do not affect score", () => {
    const findings = Array.from({ length: 10 }, () => ({
      ruleId: "x",
      severity: "info" as const,
      owasp: "MCP01" as const,
      title: "T",
      description: "D",
      remediation: "R",
      client: "C",
      configPath: "/p",
      serverName: "s",
    }));
    const { score } = calculateSecurityScore(findings);
    expect(score).toBe(100);
  });
});
