"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { scan, scanSql } = require("../src/scanner");

const ROOT = path.join(__dirname, "..");
const BAD = path.join(ROOT, "fixtures", "bad");
const GOOD = path.join(ROOT, "fixtures", "good");
const FE = path.join(ROOT, "fixtures", "frontend");
const FE_CLEAN = path.join(ROOT, "fixtures", "frontend-clean");

describe("scanSql bad fixtures", () => {
  it("flags RLS-off tables and USING (true) policies", () => {
    const fs = require("fs");
    const sql = fs.readFileSync(path.join(BAD, "001_init.sql"), "utf8");
    const { findings } = scanSql(sql, "001_init.sql");
    const checks = findings.map((f) => f.check);
    assert.ok(checks.includes("rls_disabled"), "expected rls_disabled");
    assert.ok(checks.includes("using_true"), "expected using_true");
    assert.ok(checks.includes("public_storage_bucket"), "expected public bucket");
    assert.ok(findings.some((f) => /profiles/i.test(f.message)));
  });

  it("flags update policies with using true", () => {
    const fs = require("fs");
    const sql = fs.readFileSync(path.join(BAD, "002_messages.sql"), "utf8");
    const { findings } = scanSql(sql, "002_messages.sql");
    assert.ok(findings.some((f) => f.check === "using_true"));
    assert.ok(findings.some((f) => f.policy && /update/i.test(f.message + f.policy) || f.table === "public.messages"));
  });
});

describe("scanSql good fixtures", () => {
  it("finds no critical policy mistakes on hardened schema", () => {
    const report = scan({ sql: [GOOD], cwd: ROOT });
    assert.equal(report.summary.critical, 0);
    assert.equal(report.summary.high, 0);
    assert.equal(report.summary.total, 0);
  });
});

describe("frontend service-role scan", () => {
  it("flags service role in client + NEXT_PUBLIC_SERVICE_ROLE", () => {
    const report = scan({ frontend: [FE], cwd: ROOT });
    assert.ok(report.summary.total >= 1);
    assert.ok(
      report.findings.some(
        (f) =>
          f.check === "service_role_env" ||
          f.check === "public_service_role_env_name" ||
          f.id === "service_role_env" ||
          f.id === "public_service_role_env_name" ||
          /service.?role/i.test(f.message)
      )
    );
  });

  it("passes a clean anon-only client", () => {
    const report = scan({ frontend: [FE_CLEAN], cwd: ROOT });
    assert.equal(report.summary.total, 0);
  });
});

describe("full bad tree", () => {
  it("returns critical findings and fail-worthy summary", () => {
    const report = scan({ sql: [BAD], frontend: [FE], cwd: ROOT });
    assert.ok(report.summary.critical >= 1);
    assert.ok(report.summary.total >= 3);
    assert.ok(report.meta.sqlFiles.length >= 2);
  });
});

describe("cli --demo", () => {
  it("scans the bundled fixtures and exits 1", async () => {
    const { runCli } = require("../src/cli");
    const logs = [];
    const orig = console.log;
    console.log = (m) => logs.push(String(m));
    let code;
    try {
      code = await runCli(["--demo", "--no-color"]);
    } finally {
      console.log = orig;
    }
    assert.strictEqual(code, 1);
    assert.match(logs.join("\n"), /using_true/);
    assert.match(logs.join("\n"), /rls_disabled/);
  });
});
