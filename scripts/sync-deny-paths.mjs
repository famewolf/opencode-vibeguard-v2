#!/usr/bin/env node
/**
 * sync-deny-paths: export cc-safety-net deny_paths file contents as a
 * vibeguard keywords snippet.
 *
 * Usage:
 *   node scripts/sync-deny-paths.mjs [--policy PATH] --out vibeguard.keywords.json
 *   node scripts/sync-deny-paths.mjs --policy ~/.cc-safety-net/policy.json --out /tmp/vg.json --min-len 8
 *
 * Reads each deny_paths file, extracts secret values (same extractor the
 * plugin uses at runtime), and writes `{ "keywords": [...] }` for pasting
 * into `vibeguard.config.json` under `patterns`. Prints counts only — never
 * secret values. Extra files: `--extra /path/to/file` (repeatable).
 */
import { writeFile, mkdir } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import os from "node:os"
import { loadProtectedKeywords, readDenyPaths } from "../secrets.js"

function parseArgs(argv) {
  const out = { policy: "", out: "", minLen: 8, extras: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === "--policy") out.policy = argv[++i] ?? ""
    else if (a === "--out") out.out = argv[++i] ?? ""
    else if (a === "--min-len") out.minLen = Number(argv[++i] ?? 8)
    else if (a === "--extra") out.extras.push(argv[++i] ?? "")
    else if (a === "--help" || a === "-h") {
      console.log("usage: sync-deny-paths.mjs [--policy PATH] --out FILE [--min-len N] [--extra FILE...]")
      process.exit(0)
    }
  }
  return out
}

const args = parseArgs(process.argv.slice(2))
const policy = args.policy || resolve(os.homedir(), ".cc-safety-net", "policy.json")
if (!args.out) {
  console.error("missing required --out FILE")
  process.exit(1)
}

const denyPaths = await readDenyPaths(policy)
const files = [...denyPaths, ...args.extras.filter(Boolean)]
const { keywords, failed } = await loadProtectedKeywords(files, { minLen: args.minLen, category: "SECRET_FILE" })

const outPath = resolve(process.cwd(), args.out)
await mkdir(dirname(outPath), { recursive: true })
await writeFile(outPath, `${JSON.stringify({ keywords }, null, 2)}\n`, "utf8")

console.log(`deny_paths files: ${denyPaths.length}`)
console.log(`files read: ${files.length - failed.length}/${files.length}`)
console.log(`keywords exported: ${keywords.length}`)
console.log(`wrote: ${outPath}`)
for (const f of failed) console.error(`unreadable: ${f.file}: ${f.message}`)
