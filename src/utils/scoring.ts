import type { Severity, Finding } from "../rules/types.js";

const SEVERITY_DEDUCTIONS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 2,
  info: 0,
};

export interface SecurityScore {
  score: number;
  grade: string;
  label: string;
}

export function calculateSecurityScore(findings: Finding[]): SecurityScore {
  let score = 100;
  for (const f of findings) {
    score -= SEVERITY_DEDUCTIONS[f.severity];
  }
  score = Math.max(0, score);

  let grade: string;
  let label: string;
  if (score >= 90) { grade = "A"; label = "Excellent"; }
  else if (score >= 75) { grade = "B"; label = "Good"; }
  else if (score >= 50) { grade = "C"; label = "Needs Attention"; }
  else if (score >= 25) { grade = "D"; label = "Poor"; }
  else { grade = "F"; label = "Critical Risk"; }

  return { score, grade, label };
}
