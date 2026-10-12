import { readFile } from "node:fs/promises"

const PLACEHOLDER_WORDS = new Set([
  "changeme",
  "change-me",
  "password",
  "secret",
  "example",
  "test",
  "xxx",
  "xxxx",
  "tbd",
  "todo",
  "none",
  "null",
  "undefined",
])

/**
 * Extract candidate secret values from a text file's contents.
 * Handles: single-token files, `KEY=VALUE` (.env) lines, `KEY: VALUE` (yaml)
 * lines. Skips blanks, `#` comments, short values and obvious placeholders.
 * Never logs input values; returns them only in the array.
 * @param {string} text
 * @param {{ minLen?: number, category?: string }} opts
 * @returns {string[]}
 */
export function extractSecretsFromText(text, opts) {
  const minLen = Number.isFinite(opts?.minLen) && opts.minLen > 0 ? Math.floor(opts.minLen) : 8
  const out = []
  const seen = new Set()
  const push = (v) => {
    const value = String(v ?? "").trim().replace(/^['"]+|['";,]+$/g, "").trim()
    if (value.length < minLen) return
    if (value.includes("\n") || value.includes("\r")) return
    if (/\s/.test(value)) return
    if (PLACEHOLDER_WORDS.has(value.toLowerCase())) return
    if (seen.has(value)) return
    seen.add(value)
    out.push(value)
  }

  for (const rawLine of String(text ?? "").split("\n")) {
    const line = rawLine.trim()
    if (!line || line.startsWith("#")) continue
    const eq = line.indexOf("=")
    if (eq > 0) {
      push(line.slice(eq + 1))
      continue
    }
    const colon = line.indexOf(":")
    if (colon > 0 && !line.startsWith("{") && !line.startsWith("[")) {
      push(line.slice(colon + 1))
      continue
    }
    push(line)
  }
  return out
}

const MAX_FILE_BYTES = 64 * 1024

/**
 * Read protected-file paths and return keyword entries for the pattern set.
 * Missing/unreadable files are reported in `failed`, never thrown.
 * @param {string[]} files
 * @param {{ minLen?: number, category?: string, maxBytes?: number }} opts
 */
export async function loadProtectedKeywords(files, opts) {
  const list = Array.isArray(files) ? files : []
  const category = String(opts?.category ?? "SECRET_FILE")
  const maxBytes = Number.isFinite(opts?.maxBytes) && opts.maxBytes > 0 ? opts.maxBytes : MAX_FILE_BYTES
  /** @type {Array<{value:string,category:string}>} */
  const keywords = []
  /** @type {Array<{file:string,message:string}>} */
  const failed = []
  const seen = new Set()
  for (const file of list) {
    const path = String(file ?? "").trim()
    if (!path) continue
    try {
      const text = await readFile(path, "utf8")
      const sliced = text.length > maxBytes ? text.slice(0, maxBytes) : text
      for (const value of extractSecretsFromText(sliced, opts)) {
        if (seen.has(value)) continue
        seen.add(value)
        keywords.push({ value, category })
      }
    } catch (error) {
      failed.push({ file: path, message: String(error?.message ?? error) })
    }
  }
  return { keywords, failed }
}

/**
 * Read deny_paths from a cc-safety-net policy.json file.
 * Returns [] when missing/unparsable (never throws).
 * @param {string} policyPath
 */
export async function readDenyPaths(policyPath) {
  try {
    const raw = await readFile(String(policyPath), "utf8")
    const json = JSON.parse(raw)
    const paths = json?.secret_protection?.deny_paths
    if (!Array.isArray(paths)) return []
    return paths.map((p) => String(p ?? "").trim()).filter(Boolean)
  } catch {
    return []
  }
}
