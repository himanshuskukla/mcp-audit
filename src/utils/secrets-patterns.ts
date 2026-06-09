interface SecretPattern {
  name: string;
  pattern: RegExp;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  { name: "OpenAI API Key", pattern: /^sk-(?:proj-)?[a-zA-Z0-9]{20,}$/ },
  { name: "Anthropic API Key", pattern: /^sk-ant-[a-zA-Z0-9\-_]{20,}$/ },
  {
    name: "GitHub Token",
    pattern: /^(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}$/,
  },
  { name: "AWS Access Key ID", pattern: /^AKIA[0-9A-Z]{16}$/ },
  { name: "Slack Token", pattern: /^xox[bpas]-[a-zA-Z0-9\-]+$/ },
  {
    name: "Stripe Key",
    pattern: /^(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{20,}$/,
  },
  {
    name: "Database URL",
    pattern: /^(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^:]+:[^@]+@/,
  },
  {
    name: "Bearer/Basic Auth Token",
    pattern: /^(?:Bearer|Basic)\s+[a-zA-Z0-9+/=]{20,}$/,
  },
  { name: "Generic Secret", pattern: /^[a-zA-Z0-9+/=_\-]{40,}$/ },
  { name: "Generic Secret (with dots)", pattern: /^[a-zA-Z0-9+/=_\-\.]{30,}$/ },
  { name: "Google API Key", pattern: /^AIza[0-9A-Za-z\-_]{35}$/ },
  {
    name: "Notion Token",
    pattern: /^(?:ntn_|secret_)[a-zA-Z0-9]{40,}$/,
  },
];

export function detectSecret(value: string): string | null {
  if (value.length < 8) return null;
  for (const { name, pattern } of SECRET_PATTERNS) {
    if (pattern.test(value)) {
      return name;
    }
  }
  return null;
}
