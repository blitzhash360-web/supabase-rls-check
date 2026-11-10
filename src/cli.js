"use strict";

const path = require("path");
const fs = require("fs");
const { scan } = require("./scanner");
const { formatText, formatJson } = require("./format");

const HELP = `
supabase-rls-check — offline Supabase RLS security checker

USAGE
  npx supabase-rls-check --sql <file-or-dir> [--frontend <dir>] [options]
  supabase-rls-check --sql ./supabase/migrations --frontend ./src

OPTIONS
  --sql, -s <path>         SQL dump or migrations folder (repeatable)
  --frontend, -f <path>    Frontend / env tree to scan for service-role leaks (repeatable)
  --json                   Machine-readable JSON output
  --fail-on <level>        Exit 1 when findings at this severity or worse
                           (critical|high|medium|low). Default: high
  --demo                   Scan the bundled example schema (shows every check firing)
  --no-color               Disable ANSI colors
  -h, --help               Show help
  -v, --version            Show version

WHAT IT CHECKS
  • Tables created without ENABLE ROW LEVEL SECURITY
  • Policies using USING (true) or WITH CHECK (true)
  • Public storage.buckets inserts/updates
  • service_role JWT / NEXT_PUBLIC_SERVICE_ROLE patterns in frontend files

Never pass a service-role key as a CLI flag. This tool is offline and does not
call your Supabase project. For live API tests, use a private environment.

Built by BlitzHash · https://blitzhash.com
`.trim();

function parseArgs(argv) {
  const opts = {
    sql: [],
    frontend: [],
    json: false,
    failOn: "high",
    noColor: false,
    demo: false,
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (!v || v.startsWith("-")) throw new Error(`Missing value after ${a}`);
      return v;
    };
    switch (a) {
      case "-h":
      case "--help":
        opts.help = true;
        break;
      case "-v":
      case "--version":
        opts.version = true;
        break;
      case "--json":
        opts.json = true;
        break;
      case "--demo":
        opts.demo = true;
        break;
      case "--no-color":
        opts.noColor = true;
        break;
      case "--fail-on":
        opts.failOn = next().toLowerCase();
        break;
      case "-s":
      case "--sql":
        opts.sql.push(next());
        break;
      case "-f":
      case "--frontend":
        opts.frontend.push(next());
        break;
      default:
        if (a.startsWith("-")) throw new Error(`Unknown option: ${a}`);
        // bare path → treat as sql target for convenience
        opts.sql.push(a);
    }
  }
  return opts;
}

const FAIL_ORDER = ["critical", "high", "medium", "low"];

function shouldFail(summary, failOn) {
  const idx = FAIL_ORDER.indexOf(failOn);
  if (idx < 0) return summary.total > 0;
  for (let i = 0; i <= idx; i++) {
    if (summary[FAIL_ORDER[i]] > 0) return true;
  }
  return false;
}

async function runCli(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    console.error(e.message);
    console.error("Try --help");
    return 2;
  }

  if (opts.help) {
    console.log(HELP);
    return 0;
  }
  if (opts.version) {
    const pkg = require("../package.json");
    console.log(pkg.version);
    return 0;
  }

  if (opts.demo) {
    const demoDir = path.join(__dirname, "..", "fixtures");
    opts.sql.push(path.relative(process.cwd(), path.join(demoDir, "bad")) || ".");
    opts.frontend.push(path.relative(process.cwd(), path.join(demoDir, "frontend")) || ".");
  }

  if (opts.sql.length === 0 && opts.frontend.length === 0) {
    // Sensible defaults when run in a Supabase project
    const guesses = [
      "supabase/migrations",
      "supabase",
      "migrations",
      "sql",
    ];
    for (const g of guesses) {
      if (fs.existsSync(path.resolve(g))) {
        opts.sql.push(g);
        break;
      }
    }
  }

  if (opts.sql.length === 0 && opts.frontend.length === 0) {
    console.error(
      "No targets. Pass --sql <migrations-or-dump> and/or --frontend <src>."
    );
    console.error(HELP);
    return 2;
  }

  for (const p of [...opts.sql, ...opts.frontend]) {
    if (!fs.existsSync(path.resolve(p))) {
      console.error(`Path not found: ${p}`);
      return 2;
    }
  }

  const report = scan({
    sql: opts.sql,
    frontend: opts.frontend,
    cwd: process.cwd(),
  });

  if (opts.json) {
    console.log(formatJson(report));
  } else {
    console.log(formatText(report, opts));
  }

  return shouldFail(report.summary, opts.failOn) ? 1 : 0;
}

module.exports = { runCli, parseArgs, shouldFail };
