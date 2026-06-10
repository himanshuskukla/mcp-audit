interface Env {
  DB: D1Database;
}

const REQUIRED_FIELDS = ["v", "ts", "os", "clients", "serverCount", "score", "grade", "live", "findings", "rulesFired", "totalFindings"] as const;

function validatePayload(body: any): string | null {
  if (!body || typeof body !== "object") return "Body must be a JSON object";
  for (const field of REQUIRED_FIELDS) {
    if (body[field] === undefined) return `Missing required field: ${field}`;
  }
  if (typeof body.v !== "string" || body.v.length === 0 || body.v.length > 20) return "v must be a non-empty string (max 20 chars)";
  if (typeof body.os !== "string") return "os must be a string";
  if (!Array.isArray(body.clients)) return "clients must be an array";
  if (typeof body.serverCount !== "number" || body.serverCount < 0) return "serverCount must be a non-negative number";
  if (typeof body.score !== "number" || body.score < 0 || body.score > 100) return "score must be 0-100";
  if (typeof body.grade !== "string") return "grade must be a string";
  if (typeof body.live !== "boolean") return "live must be a boolean";
  if (typeof body.findings !== "object" || Array.isArray(body.findings)) return "findings must be an object";
  if (!Array.isArray(body.rulesFired)) return "rulesFired must be an array";
  if (typeof body.totalFindings !== "number") return "totalFindings must be a number";
  return null;
}

async function handleReport(request: Request, env: Env): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const error = validatePayload(body);
  if (error) return Response.json({ error }, { status: 400 });

  const clean = {
    v: body.v, os: body.os, arch: body.arch, nodeVersion: body.nodeVersion,
    clients: body.clients, serverCount: body.serverCount, score: body.score,
    grade: body.grade, live: body.live, findings: body.findings,
    rulesFired: body.rulesFired, totalFindings: body.totalFindings,
  };

  await env.DB.prepare(`
    INSERT INTO reports (version, os, arch, node_ver, clients, server_count, score, grade, live, findings, rules_fired, total_findings)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    clean.v,
    clean.os,
    clean.arch ?? null,
    clean.nodeVersion ?? null,
    JSON.stringify(clean.clients),
    clean.serverCount,
    clean.score,
    clean.grade,
    clean.live ? 1 : 0,
    JSON.stringify(clean.findings),
    JSON.stringify(clean.rulesFired),
    clean.totalFindings,
  ).run();

  return Response.json({ ok: true });
}

async function handleStats(env: Env): Promise<Response> {
  const totalRow = await env.DB.prepare("SELECT COUNT(*) as cnt, AVG(score) as avg_score FROM reports").first();
  const gradeRows = await env.DB.prepare("SELECT grade, COUNT(*) as cnt FROM reports GROUP BY grade").all();
  const osRows = await env.DB.prepare("SELECT os, COUNT(*) as cnt FROM reports GROUP BY os").all();

  const totalScans = (totalRow?.cnt as number) ?? 0;
  const avgScore = totalScans > 0 ? Math.round(totalRow?.avg_score as number) : 0;

  const gradeDistribution: Record<string, number> = {};
  for (const row of gradeRows.results) {
    gradeDistribution[row.grade as string] = row.cnt as number;
  }

  const osByPct: Record<string, number> = {};
  for (const row of osRows.results) {
    osByPct[row.os as string] = totalScans > 0 ? Math.round(((row.cnt as number) / totalScans) * 100) : 0;
  }

  const allFindings = await env.DB.prepare("SELECT findings FROM reports").all();
  const ruleCounts: Record<string, number> = {};
  for (const row of allFindings.results) {
    const findings = JSON.parse(row.findings as string);
    for (const rule of Object.keys(findings)) {
      ruleCounts[rule] = (ruleCounts[rule] ?? 0) + 1;
    }
  }
  const topRules = Object.entries(ruleCounts)
    .map(([rule, count]) => ({ rule, pct: totalScans > 0 ? Math.round((count / totalScans) * 100) : 0 }))
    .sort((a, b) => b.pct - a.pct)
    .slice(0, 10);

  const stats = { totalScans, avgScore, gradeDistribution, topRules, osByPct };

  return Response.json(stats, {
    headers: {
      "Cache-Control": "public, max-age=300",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/v1/report") {
      return handleReport(request, env);
    }

    if (request.method === "GET" && url.pathname === "/v1/stats") {
      return handleStats(env);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    return Response.json({ error: "Not found" }, { status: 404 });
  },
};
