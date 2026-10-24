#!/usr/bin/env node
/*
 * Reproducible structural baseline against PhishLens.
 *
 * Usage:
 *   git clone https://github.com/Georgefifth/phishlens.git /tmp/phishlens
 *   swift build
 *   node scripts/baseline-compare.js /tmp/phishlens/engine.js
 *
 * ScamShield is invoked through its own CLI with no --live flag, so no network
 * request is made. PhishLens is executed locally with its zero-dependency engine.
 * Labels live in evaluation/holdout-urls.json and are never passed to either
 * detector. "Detected" means medium or above for ScamShield and suspicious or
 * dangerous for PhishLens; "phishing" requires high/critical/dangerous in the
 * stricter columns.
 */
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const enginePath = process.argv[2];
if (!enginePath) {
  console.error("usage: node scripts/baseline-compare.js /path/to/phishlens/engine.js");
  process.exit(64);
}

const root = path.resolve(__dirname, "..");
const cli = path.join(root, ".build", "debug", "scamshieldctl");
const fixtures = JSON.parse(fs.readFileSync(path.join(root, "evaluation", "holdout-urls.json"), "utf8"));
const phishlens = require(path.resolve(enginePath));

function scamshield(url) {
  // Exit codes encode risk (0 low, 1 medium, 2 high/critical, 3 unverified), so a
  // non-zero status is expected and not an execution failure.
  const result = spawnSync(cli, ["scan-url", url, "--json"], { encoding: "utf8" });
  if (result.error) throw result.error;
  return JSON.parse(result.stdout);
}

const rows = [];
for (const fixture of fixtures) {
  const ss = scamshield(fixture.url);
  const pl = phishlens.analyzeUrl(fixture.url);
  const ssLevel = ss.riskLevel || "unknown";
  const ssMedium = ["medium", "high", "critical"].includes(ssLevel);
  const ssHigh = ["high", "critical"].includes(ssLevel);
  const plMedium = ["suspicious", "dangerous"].includes(pl.level);
  const plHigh = pl.level === "dangerous";
  rows.push({ ...fixture, ssLevel, ssScore: ss.riskScore,
              plLevel: pl.level, plScore: pl.score, ssMedium, ssHigh, plMedium, plHigh });
}

const width = 30;
console.log(`${"fixture".padEnd(width)} ${"label".padEnd(10)} ${"ScamShield".padEnd(16)} ${"score".padStart(5)} ${"PhishLens".padEnd(13)} ${"score".padStart(5)}`);
for (const row of rows) {
  console.log(`${row.id.padEnd(width)} ${row.label.padEnd(10)} ${row.ssLevel.padEnd(16)} ${String(row.ssScore).padStart(5)} ${row.plLevel.padEnd(13)} ${String(row.plScore).padStart(5)}`);
}

function metrics(name, positive, negative, hostile, benign) {
  let tp = 0, fn = 0, fp = 0, tn = 0;
  for (const row of rows) {
    if (!hostile.has(row) && !benign.has(row)) continue;
    const detected = positive(row);
    if (benign.has(row)) {
      detected ? fp++ : tn++;
    } else {
      detected ? tp++ : fn++;
    }
  }
  const precision = tp + fp ? (tp / (tp + fp)).toFixed(3) : "0.000";
  const recall = tp + fn ? (tp / (tp + fn)).toFixed(3) : "0.000";
  return { name, tp, fn, fp, tn, precision, recall, hostile: hostile.size, benign: benign.size };
}

const hostile = new Set(rows.filter(r => r.label !== "benign"));
const benign = new Set(rows.filter(r => r.label === "benign"));
console.log("\nDetection at the inclusive threshold (ScamShield medium+, PhishLens suspicious+):");
console.table(metrics("ScamShield", r => r.ssMedium, r => !r.ssMedium, hostile, benign));
console.table(metrics("PhishLens", r => r.plMedium, r => !r.plMedium, hostile, benign));
const phishing = new Set(rows.filter(r => r.label === "phishing"));
console.log("Strict threshold (ScamShield high+, PhishLens dangerous), phishing-labelled rows only:");
console.table(metrics("ScamShield strict", r => r.ssHigh, r => !r.ssHigh, phishing, benign));
console.table(metrics("PhishLens strict", r => r.plHigh, r => !r.plHigh, phishing, benign));
