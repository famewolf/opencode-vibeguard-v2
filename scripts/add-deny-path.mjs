#!/usr/bin/env node
/**
 * add-deny-path — manage the deny_paths list consumed by vibeguard's
 * `import_deny_paths` option (same file cc-safety-net uses).
 *
 * Usage:
 *   node scripts/add-deny-path.mjs /absolute/path/to/secret-file
 *   node scripts/add-deny-path.mjs list
 *   node scripts/add-deny-path.mjs --init [--policy PATH]
 *   node scripts/add-deny-path.mjs --help
 *
 * Options:
 *   --policy PATH   policy file (default ~/.cc-safety-net/policy.json)
 *   --init          create the policy file with an empty deny_paths list
 *                   when it does not exist yet (for users without cc-safety-net)
 *
 * Prints paths and counts only — never file contents. Writes atomically:
 * the policy file is only replaced when the new content parses cleanly.
 */
import { readFile, writeFile, rename, unlink, mkdir } from "node:fs/promises"
import { dirname, resolve, isAbsolute } from "node:path"
import os from "node:os"

const DEFAULT_POLICY = resolve(os.homedir(), ".cc-safety-net", "policy.json")
const USAGE = `usage:
  add-deny-path.mjs /absolute/path   add a path to deny_paths (idempotent)
  add-deny-path.mjs list             show all paths currently denied
  add-deny-path.mjs --init           create an empty policy file if missing
  add-deny-path.mjs --help           show this help

options:
  --policy PATH   policy file (default ${DEFAULT_POLICY})`

function parseArgs(argv) {
  const out = { policy: DEFAULT_POLICY, init: false, help: false, positional: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === "--policy") out.policy = resolve(argv[++i] ?? "")
    else if (a === "--init") out.init = true
    else if (a === "--help" || a === "-h") out.help = true
    else out.positional.push(a)
  }
  return out
}

async function loadPolicy(policyPath, init) {
  try {
    const json = JSON.parse(await readFile(policyPath, "utf8"))
    if (!Array.isArray(json?.secret_protection?.deny_paths)) {
      console.error(`policy has no secret_protection.deny_paths array: ${policyPath}`)
      process.exit(1)
    }
    return json
  } catch (error) {
    if (error?.code === "ENOENT" && init) {
      return { version: 1, secret_protection: { deny_paths: [] } }
    }
    console.error(`cannot read policy: ${policyPath}: ${String(error?.message ?? error)}`)
    process.exit(1)
  }
}

const args = parseArgs(process.argv.slice(2))
if (args.help) {
  console.log(USAGE)
  process.exit(0)
}

const [command] = args.positional
if (!command && !args.init) {
  console.error(USAGE)
  process.exit(1)
}

const policy = await loadPolicy(args.policy, args.init)

if (command === "list") {
  for (const p of policy.secret_protection.deny_paths) console.log(p)
  process.exit(0)
}

if (command) {
  if (!isAbsolute(command)) {
    console.error(`refusing relative path: ${command}`)
    process.exit(1)
  }
  const list = policy.secret_protection.deny_paths
  if (!list.includes(command)) list.push(command)
  const tmp = `${args.policy}.tmp`
  await mkdir(dirname(args.policy), { recursive: true })
  try {
    await writeFile(tmp, `${JSON.stringify(policy, null, 2)}\n`, "utf8")
    JSON.parse(await readFile(tmp, "utf8"))
    await rename(tmp, args.policy)
  } catch (error) {
    await unlink(tmp).catch(() => {})
    console.error(`write failed; policy untouched: ${String(error?.message ?? error)}`)
    process.exit(1)
  }
  console.log(`deny_paths now has ${list.length} entries`)
  for (const p of list) console.log(p)
} else if (args.init) {
  // Bare --init: persist the skeleton created by loadPolicy.
  const tmp = `${args.policy}.tmp`
  await mkdir(dirname(args.policy), { recursive: true })
  await writeFile(tmp, `${JSON.stringify(policy, null, 2)}\n`, "utf8")
  await rename(tmp, args.policy)
  console.log(`created: ${args.policy}`)
}
