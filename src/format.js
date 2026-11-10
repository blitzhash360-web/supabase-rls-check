"use strict";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const GREEN = "\x1b[32m";
const MAGENTA = "\x1b[35m";

function colorEnabled(opts) {
  if (opts.json) return false;
  if (opts.noColor || process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== "0") return true;
  return process.stdout.isTTY === true;
}

function paint(enabled, code, s) {
  return enabled ? `${code}${s}${RESET}` : s;
}

function formatText(report, opts = {}) {
  const c = colorEnabled(opts);
  const lines = [];
  const { findings, summary, meta } = report;

  lines.push(paint(c, BOLD + CYAN, "supabase-rls-check") + paint(c, DIM, " · offline Supabase RLS audit"));
  lines.push(
    paint(c, DIM, `SQL files: ${meta.sqlFiles.length} · frontend files: ${meta.frontendFiles.length}`)
  );
  lines.push("");

  if (findings.length === 0) {
    lines.push(paint(c, GREEN + BOLD, "✓ No issues found."));
    lines.push(
      paint(
        c,
        DIM,
        "Still run an Empty-Account Test in the browser before you ship."
      )
    );
    return lines.join("\n");
  }

  for (const f of findings) {
    const sevColor =
      f.severity === "critical"
        ? RED
        : f.severity === "high"
          ? YELLOW
          : MAGENTA;
    const tag = paint(c, sevColor + BOLD, f.severity.toUpperCase());
    const check = paint(c, DIM, `[${f.check}]`);
    lines.push(`${tag} ${check} ${f.message}`);
    if (f.source) lines.push(paint(c, DIM, `       source: ${f.source}`));
    if (f.file) lines.push(paint(c, DIM, `       file: ${f.file}`));
    if (f.hint) lines.push(paint(c, CYAN, `       fix: ${f.hint}`));
    lines.push("");
  }

  const parts = [];
  if (summary.critical)
    parts.push(paint(c, RED + BOLD, `${summary.critical} critical`));
  if (summary.high) parts.push(paint(c, YELLOW + BOLD, `${summary.high} high`));
  if (summary.medium) parts.push(`${summary.medium} medium`);
  if (summary.low) parts.push(`${summary.low} low`);
  lines.push(
    paint(c, BOLD, "Summary: ") +
      parts.join(", ") +
      paint(c, DIM, ` (${summary.total} total)`)
  );
  lines.push("");
  lines.push(
    paint(
      c,
      DIM,
      "Built by BlitzHash · https://blitzhash.com · never paste a service-role key into a public issue"
    )
  );
  return lines.join("\n");
}

function formatJson(report) {
  return JSON.stringify(
    {
      summary: report.summary,
      findings: report.findings,
      meta: {
        sqlFiles: report.meta.sqlFiles,
        frontendFiles: report.meta.frontendFiles,
        tableCount: report.meta.tables.length,
      },
    },
    null,
    2
  );
}

module.exports = { formatText, formatJson };
