"use strict";

const fs = require("fs");
const path = require("path");

const SQL_EXTS = new Set([".sql", ".pgsql", ".psql"]);
const FRONTEND_EXTS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".vue", ".svelte", ".html", ".json", ".env", ".env.local", ".env.production",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", "dist", "build", ".turbo",
  "coverage", ".vercel", ".supabase", "vendor", "__pycache__",
]);

/**
 * Walk a directory and collect files matching an extension set.
 */
function walkFiles(root, exts, out = []) {
  if (!fs.existsSync(root)) return out;
  const st = fs.statSync(root);
  if (st.isFile()) {
    const ext = path.extname(root).toLowerCase();
    const base = path.basename(root).toLowerCase();
    if (exts.has(ext) || exts.has(base)) out.push(root);
    return out;
  }
  for (const name of fs.readdirSync(root)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = path.join(root, name);
    let child;
    try {
      child = fs.statSync(full);
    } catch {
      continue;
    }
    if (child.isDirectory()) walkFiles(full, exts, out);
    else {
      const ext = path.extname(name).toLowerCase();
      const base = name.toLowerCase();
      if (exts.has(ext) || exts.has(base)) out.push(full);
    }
  }
  return out;
}

function stripSqlComments(sql) {
  // Remove /* block */ then -- line comments (rough but good enough for audits)
  let s = sql.replace(/\/\*[\s\S]*?\*\//g, " ");
  s = s.replace(/--[^\n]*/g, " ");
  return s;
}

function normalizeSql(sql) {
  return stripSqlComments(sql).replace(/\s+/g, " ").trim();
}

/**
 * Extract CREATE TABLE names (schema-qualified when present).
 */
function findCreateTables(sql) {
  const tables = [];
  const re =
    /\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:"?[\w$]+"?\.)?"?[\w$]+"?)/gi;
  let m;
  while ((m = re.exec(sql))) {
    tables.push(cleanIdent(m[1]));
  }
  return tables;
}

function cleanIdent(id) {
  return String(id).replace(/^"|"$/g, "").replace(/"/g, "").toLowerCase();
}

/**
 * Tables that have RLS enabled via ALTER TABLE ... ENABLE ROW LEVEL SECURITY
 */
function findRlsEnabled(sql) {
  const enabled = new Set();
  const re =
    /\bALTER\s+TABLE\s+((?:"?[\w$]+"?\.)?"?[\w$]+"?)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY\b/gi;
  let m;
  while ((m = re.exec(sql))) enabled.add(cleanIdent(m[1]));
  return enabled;
}

function findRlsDisabled(sql) {
  const disabled = new Set();
  const re =
    /\bALTER\s+TABLE\s+((?:"?[\w$]+"?\.)?"?[\w$]+"?)\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY\b/gi;
  let m;
  while ((m = re.exec(sql))) disabled.add(cleanIdent(m[1]));
  return disabled;
}

/**
 * Parse CREATE POLICY statements and flag permissive true policies.
 */
function findPolicies(sql) {
  const policies = [];
  // Quoted policy names may contain spaces: "Enable read access for all users"
  const simple =
    /\bCREATE\s+POLICY\s+("(?:[^"]+)"|[\w$]+)\s+ON\s+((?:"?[\w$]+"?\.)?"?[\w$]+"?)\s+([\s\S]*?);/gi;
  let m;
  while ((m = simple.exec(sql))) {
    const name = cleanIdent(m[1]);
    const table = cleanIdent(m[2]);
    const body = m[3].replace(/\s+/g, " ").trim();
    const usingTrue = /\bUSING\s*\(\s*true\s*\)/i.test(body);
    const checkTrue = /\bWITH\s+CHECK\s*\(\s*true\s*\)/i.test(body);
    const forAll = /\bFOR\s+ALL\b/i.test(body);
    const forSelect = /\bFOR\s+SELECT\b/i.test(body);
    const forInsert = /\bFOR\s+INSERT\b/i.test(body);
    const forUpdate = /\bFOR\s+UPDATE\b/i.test(body);
    const forDelete = /\bFOR\s+DELETE\b/i.test(body);
    const toPublic = /\bTO\s+(public|anon|authenticated)\b/i.test(body);
    policies.push({
      name,
      table,
      body,
      usingTrue,
      checkTrue,
      forAll,
      forSelect,
      forInsert,
      forUpdate,
      forDelete,
      toPublic,
    });
  }
  return policies;
}

function findPublicBuckets(sql) {
  const findings = [];
  // UPDATE ... SET public = true
  const upd =
    /\bUPDATE\s+storage\.buckets\b[\s\S]*?\bSET\s+[\s\S]*?\bpublic\s*=\s*true\b/gi;
  let m;
  while ((m = upd.exec(sql))) {
    findings.push({ kind: "update", snippet: m[0].slice(0, 120).replace(/\s+/g, " ") });
  }
  // INSERT INTO storage.buckets
  const ins =
    /\bINSERT\s+INTO\s+storage\.buckets\b[\s\S]*?;/gi;
  while ((m = ins.exec(sql))) {
    const block = m[0];
    // crude: if VALUES has true near public column, or column list includes public and a true appears
    if (/\bpublic\b/i.test(block) && /\btrue\b/i.test(block)) {
      findings.push({ kind: "insert", snippet: block.slice(0, 160).replace(/\s+/g, " ") });
    }
  }
  return findings;
}

/**
 * Scan frontend / env files for service_role key patterns (never print the secret).
 */
function findServiceRoleLeaks(content, filePath) {
  const findings = [];
  const patterns = [
    {
      id: "service_role_env",
      re: /SUPABASE_SERVICE[_-]?ROLE[_-]?KEY\s*[=:]\s*['"]?eyJ[A-Za-z0-9_-]{20,}/i,
      message: "Hardcoded service-role JWT in source or env file",
    },
    {
      id: "service_role_literal",
      re: /service[_-]?role['"]?\s*[:=]\s*['"]eyJ[A-Za-z0-9_-]{20,}/i,
      message: "service_role JWT literal in client/source code",
    },
    {
      id: "createClient_service",
      re: /createClient\s*\(\s*[^,)]+\s*,\s*['"]eyJ[A-Za-z0-9_-]{80,}['"]/i,
      message: "createClient() may be using a long JWT (possible service role) in a frontend file",
    },
    {
      id: "role_service_role_string",
      re: /['"]service_role['"]\s*,\s*['"]eyJ/i,
      message: "Explicit service_role credential pair in source",
    },
  ];
  const base = path.basename(filePath).toLowerCase();
  const isFrontendish =
    /\.(jsx?|tsx?|vue|svelte|html|mjs|cjs)$/i.test(filePath) ||
    base.startsWith(".env");
  if (!isFrontendish && !/\.(json)$/i.test(filePath)) return findings;

  for (const p of patterns) {
    if (p.re.test(content)) {
      findings.push({ id: p.id, message: p.message, file: filePath });
    }
  }
  // Flag NEXT_PUBLIC / VITE_ / PUBLIC_ prefixed service role env names
  if (
    /(?:NEXT_PUBLIC|VITE|PUBLIC)_[A-Z0-9_]*SERVICE[_-]?ROLE/i.test(content)
  ) {
    findings.push({
      id: "public_service_role_env_name",
      message:
        "Service-role env var name is prefixed for the browser (NEXT_PUBLIC_/VITE_/PUBLIC_)",
      file: filePath,
    });
  }
  return findings;
}

function severityRank(s) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 9;
}

/**
 * Scan SQL text and produce findings.
 */
function scanSql(sql, sourceLabel) {
  const findings = [];
  const tables = findCreateTables(sql);
  const enabled = findRlsEnabled(sql);
  const disabled = findRlsDisabled(sql);
  const policies = findPolicies(sql);

  for (const t of tables) {
    // Skip storage/auth system schemas if fully qualified
    if (t.startsWith("auth.") || t.startsWith("storage.") || t.startsWith("realtime.")) {
      continue;
    }
    const short = t.includes(".") ? t.split(".").pop() : t;
    const isEnabled =
      enabled.has(t) ||
      enabled.has(short) ||
      [...enabled].some((e) => e.endsWith(`.${short}`) || e === short);
    const isDisabled =
      disabled.has(t) ||
      disabled.has(short) ||
      [...disabled].some((e) => e.endsWith(`.${short}`) || e === short);

    if (isDisabled || !isEnabled) {
      findings.push({
        severity: "critical",
        check: "rls_disabled",
        table: t,
        source: sourceLabel,
        message: isDisabled
          ? `Table "${t}" has RLS explicitly DISABLED`
          : `Table "${t}" is created but RLS is never enabled`,
        hint: `Run: alter table ${t} enable row level security; then add policies that check auth.uid().`,
      });
    }
  }

  for (const p of policies) {
    if (p.usingTrue || p.checkTrue) {
      const parts = [];
      if (p.usingTrue) parts.push("USING (true)");
      if (p.checkTrue) parts.push("WITH CHECK (true)");
      const open =
        p.forAll ||
        (p.forSelect && p.usingTrue) ||
        (p.forInsert && p.checkTrue) ||
        (p.forUpdate && (p.usingTrue || p.checkTrue)) ||
        (p.forDelete && p.usingTrue);
      findings.push({
        severity: open || p.forAll ? "critical" : "high",
        check: "using_true",
        table: p.table,
        policy: p.name,
        source: sourceLabel,
        message: `Policy "${p.name}" on "${p.table}" uses ${parts.join(" and ")} — anyone who can hit the API can read/write matching rows`,
        hint: "Rewrite the policy to compare a column to auth.uid() (or your tenant id). Deny by default.",
      });
    }
  }

  for (const b of findPublicBuckets(sql)) {
    findings.push({
      severity: "high",
      check: "public_storage_bucket",
      source: sourceLabel,
      message: `Public storage bucket detected (${b.kind})`,
      snippet: b.snippet,
      hint: "Keep buckets private and serve files through signed URLs, or restrict with storage RLS policies.",
    });
  }

  return { findings, tables, enabled: [...enabled], policies };
}

function scanFrontendFile(filePath) {
  let content;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch {
    return [];
  }
  // Skip huge minified bundles over 2MB but still sample first/last chunks
  if (content.length > 2_000_000) {
    content = content.slice(0, 500_000) + "\n" + content.slice(-500_000);
  }
  return findServiceRoleLeaks(content, filePath);
}

/**
 * Main entry: scan paths (files or directories).
 * options: { sql: string[], frontend: string[], cwd }
 */
function scan(options = {}) {
  const cwd = options.cwd || process.cwd();
  const sqlTargets = (options.sql || []).map((p) => path.resolve(cwd, p));
  const frontendTargets = (options.frontend || []).map((p) =>
    path.resolve(cwd, p)
  );

  const allFindings = [];
  const meta = { sqlFiles: [], frontendFiles: [], tables: [] };

  for (const target of sqlTargets) {
    const files = walkFiles(target, SQL_EXTS);
    if (files.length === 0 && fs.existsSync(target) && fs.statSync(target).isFile()) {
      files.push(target);
    }
    for (const f of files) {
      meta.sqlFiles.push(f);
      const sql = fs.readFileSync(f, "utf8");
      const rel = path.relative(cwd, f) || f;
      const result = scanSql(sql, rel);
      meta.tables.push(...result.tables);
      allFindings.push(...result.findings);
    }
  }

  for (const target of frontendTargets) {
    const files = walkFiles(target, FRONTEND_EXTS);
    if (files.length === 0 && fs.existsSync(target) && fs.statSync(target).isFile()) {
      files.push(target);
    }
    for (const f of files) {
      meta.frontendFiles.push(f);
      for (const hit of scanFrontendFile(f)) {
        allFindings.push({
          severity: "critical",
          check: hit.id,
          file: path.relative(cwd, hit.file) || hit.file,
          message: hit.message,
          hint: "Keep the service-role key on the server only (Edge Function, API route, or CI secret). Never prefix it with NEXT_PUBLIC_, VITE_, or PUBLIC_.",
        });
      }
    }
  }

  // Deduplicate identical messages
  const seen = new Set();
  const findings = [];
  for (const f of allFindings) {
    const key = `${f.check}|${f.table || ""}|${f.policy || ""}|${f.file || ""}|${f.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(f);
  }

  findings.sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      (a.table || "").localeCompare(b.table || "")
  );

  const summary = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    total: findings.length,
  };

  return { findings, summary, meta };
}

module.exports = {
  scan,
  scanSql,
  findPolicies,
  findCreateTables,
  findRlsEnabled,
  findServiceRoleLeaks,
  walkFiles,
};
