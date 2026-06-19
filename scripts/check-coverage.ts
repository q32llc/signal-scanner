import { readFileSync } from "node:fs";

const [, , lcovPath, thresholdArg] = process.argv;
const threshold = Number(thresholdArg ?? 80);

if (!lcovPath || !Number.isFinite(threshold)) {
  console.error("Usage: bun scripts/check-coverage.ts <lcov.info> <line-threshold-percent>");
  process.exit(2);
}

const lcov = readFileSync(lcovPath, "utf8");
let found = 0;
let hit = 0;

for (const line of lcov.split(/\r?\n/)) {
  if (line.startsWith("LF:")) found += Number(line.slice(3));
  else if (line.startsWith("LH:")) hit += Number(line.slice(3));
}

if (!found) {
  console.error(`No line coverage data found in ${lcovPath}`);
  process.exit(2);
}

const pct = (hit / found) * 100;
const display = pct.toFixed(2);

if (pct < threshold) {
  console.error(`Line coverage ${display}% is below required ${threshold}%`);
  process.exit(1);
}

console.log(`Line coverage ${display}% meets required ${threshold}%`);
