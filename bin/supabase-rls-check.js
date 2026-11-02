#!/usr/bin/env node
"use strict";

const { runCli } = require("../src/cli");

runCli(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    console.error(err && err.stack ? err.stack : err);
    process.exit(2);
  }
);
