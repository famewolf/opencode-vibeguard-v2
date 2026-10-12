function sanitizeCategory(input) {
  const raw = String(input ?? "").trim()
  if (!raw) return "TEXT"
  const upper = raw.toUpperCase()
  const safe = upper.replace(/[^A-Z0-9_]/g, "_").replace(/_+/g, "_")
  if (!safe) return "TEXT"
  return safe
}

/**
 * Lightweight compatibility for Go-style `(?i)` / `(?m)` prefixes (only leading flags).
 * @param {string} pattern
 * @param {string} flags
 */
function peelInlineFlags(pattern, flags) {
  let p = String(pattern ?? "")
  let f = String(flags ?? "")

  for (;;) {
    if (p.startsWith("(?i)")) {
      p = p.slice(4)
      if (!f.includes("i")) f += "i"
      continue
    }
    if (p.startsWith("(?m)")) {
      p = p.slice(4)
      if (!f.includes("m")) f += "m"
      continue
    }
    break
  }

  return { pattern: p, flags: f }
}

/**
 * Secret rules: high-signal token/password shapes. Enabled by default
 * (builtin group "secrets") so a fresh config protects front-side without
 * hand-listing every value. Pass an explicit `builtin` list to opt out.
 */
const SECRET_RULES = new Map([
  ["openai_key", { pattern: String.raw`sk-[A-Za-z0-9]{48}`, flags: "", category: "OPENAI_KEY" }],
  ["anthropic_key", { pattern: String.raw`sk-ant-[A-Za-z0-9\-_]{20,}`, flags: "", category: "ANTHROPIC_KEY" }],
  ["google_api_key", { pattern: String.raw`AIza[0-9A-Za-z\-_]{35}`, flags: "", category: "GOOGLE_API_KEY" }],
  ["github_token", { pattern: String.raw`gh[pousr]_[A-Za-z0-9_]{8,}`, flags: "", category: "GITHUB_TOKEN" }],
  ["github_pat", { pattern: String.raw`github_pat_[A-Za-z0-9_]{22,}`, flags: "", category: "GITHUB_TOKEN" }],
  ["gitlab_token", { pattern: String.raw`glpat-[A-Za-z0-9\-_]{20,}`, flags: "", category: "GITLAB_TOKEN" }],
  ["aws_access_key", { pattern: String.raw`AKIA[0-9A-Z]{16}`, flags: "", category: "AWS_ACCESS_KEY" }],
  [
    "aws_secret",
    {
      pattern: String.raw`aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`,
      flags: "i",
      category: "AWS_SECRET",
    },
  ],
  [
    "slack_token",
    {
      pattern: String.raw`(?:xox[bap]-|xapp-|xwfp-)[A-Za-z0-9\-]+`,
      flags: "",
      category: "SLACK_TOKEN",
    },
  ],
  [
    "slack_webhook",
    {
      pattern: String.raw`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`,
      flags: "",
      category: "SLACK_WEBHOOK",
    },
  ],
  [
    "stripe_key",
    {
      pattern: String.raw`[sr]k_(live|test)_[0-9a-zA-Z]{24,}`,
      flags: "",
      category: "STRIPE_KEY",
    },
  ],
  ["stripe_publishable", { pattern: String.raw`pk_(live|test)_[0-9a-zA-Z]{24,}`, flags: "", category: "STRIPE_KEY" }],
  ["npm_token", { pattern: String.raw`npm_[A-Za-z0-9]{20,}`, flags: "", category: "NPM_TOKEN" }],
  ["pypi_token", { pattern: String.raw`pypi-[A-Za-z0-9_\-]{20,}`, flags: "", category: "PYPI_TOKEN" }],
  [
    "private_key",
    {
      pattern: String.raw`-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY`,
      flags: "",
      category: "PRIVATE_KEY",
    },
  ],
  [
    "database_url",
    {
      pattern: String.raw`(?:postgres|mysql|mongodb|redis|amqp)://[^/\s:]+:[^/\s@]+@[^\s]+`,
      flags: "i",
      category: "DATABASE_URL",
    },
  ],
  [
    "generic_secret",
    {
      pattern: String.raw`(?:password|passwd|secret|api[_-]?key|apikey|access_token|auth_token)[\s"']*\s*[:=]+\s*['"]?[^'"\s;,}]{4,}['"]?`,
      flags: "i",
      category: "GENERIC_SECRET",
    },
  ],
])

const SECRET_GROUP = [...SECRET_RULES.keys()]
const BUILTIN = new Map([
  [
    "email",
    {
      pattern: String.raw`[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
      flags: "i",
      category: "EMAIL",
    },
  ],
  [
    "china_phone",
    {
      // Matches the phone number body directly (lookaround replaces Go capture-group boundary style)
      pattern: String.raw`(?<!\d)1[3-9]\d{9}(?!\d)`,
      flags: "",
      category: "CHINA_PHONE",
    },
  ],
  [
    "china_id",
    {
      pattern: String.raw`(?<!\d)\d{17}[\dXx](?!\d)`,
      flags: "",
      category: "CHINA_ID",
    },
  ],
  [
    "uuid",
    {
      pattern: String.raw`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}`,
      flags: "",
      category: "UUID",
    },
  ],
  [
    "ipv4",
    {
      // Strict 0-255 per-octet validation with boundary guards so version
      // strings and out-of-range quads do not burn mappings.
      pattern: String.raw`(?<![\w.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\w.])`,
      flags: "",
      category: "IPV4",
    },
  ],
  [
    "mac",
    {
      pattern: String.raw`(?:[0-9a-f]{2}:){5}[0-9a-f]{2}`,
      flags: "i",
      category: "MAC",
    },
  ],
])

function compileRegexRule(pattern, flags, category, errors) {
  const peeled = peelInlineFlags(pattern, flags)
  const finalFlags = peeled.flags.includes("g") ? peeled.flags : `${peeled.flags}g`
  try {
    return { regex: new RegExp(peeled.pattern, finalFlags), category }
  } catch (error) {
    errors.push({
      pattern: peeled.pattern,
      flags: finalFlags,
      message: String(error?.message ?? error),
    })
    return null
  }
}

export function buildPatternSet(patterns) {
  const raw = patterns && typeof patterns === "object" ? patterns : {}

  const keywords = Array.isArray(raw.keywords) ? raw.keywords : []
  const regex = Array.isArray(raw.regex) ? raw.regex : []
  // Default-on secrets: an absent `builtin` key means ["secrets"]. An explicit
  // list (even empty) is respected verbatim so users can opt out.
  const builtin = raw.builtin === undefined ? ["secrets"] : Array.isArray(raw.builtin) ? raw.builtin : []
  const exclude = Array.isArray(raw.exclude) ? raw.exclude : []
  const maxTextChars =
    Number.isFinite(raw.max_text_chars) && Number(raw.max_text_chars) > 0
      ? Math.floor(Number(raw.max_text_chars))
      : 500000
  const minSecretLen =
    Number.isFinite(raw.min_secret_len) && Number(raw.min_secret_len) > 0
      ? Math.floor(Number(raw.min_secret_len))
      : 8

  const keywordRules = keywords
    .map((x) => {
      if (!x || typeof x !== "object") return null
      const value = String(x.value ?? "").trim()
      if (!value) return null
      const category = sanitizeCategory(x.category)
      return { value, category }
    })
    .filter(Boolean)

  const regexRules = []
  const errors = []

  for (const x of regex) {
    if (!x || typeof x !== "object") continue
    const pattern = String(x.pattern ?? "").trim()
    if (!pattern) continue
    const category = sanitizeCategory(x.category)
    const flags = typeof x.flags === "string" ? x.flags : ""
    const rule = compileRegexRule(pattern, flags, category, errors)
    if (rule) regexRules.push(rule)
  }

  for (const name of builtin) {
    const key = String(name ?? "").trim()
    if (!key) continue
    if (key === "secrets" || key === "all") {
      const names = key === "secrets" ? SECRET_GROUP : [...BUILTIN.keys(), ...SECRET_GROUP]
      for (const secretName of names) {
        const rule = key === "secrets" ? SECRET_RULES.get(secretName) : (BUILTIN.get(secretName) ?? SECRET_RULES.get(secretName))
        if (!rule) continue
        const compiled = compileRegexRule(rule.pattern, rule.flags, rule.category, errors)
        if (compiled) regexRules.push(compiled)
      }
      continue
    }
    const rule = BUILTIN.get(key) ?? SECRET_RULES.get(key)
    if (!rule) continue
    const compiled = compileRegexRule(rule.pattern, rule.flags, rule.category, errors)
    if (compiled) regexRules.push(compiled)
  }

  const excludeSet = new Set(exclude.map((x) => String(x ?? "")))

  return {
    keywords: keywordRules,
    regex: regexRules,
    exclude: excludeSet,
    errors,
    maxTextChars,
    minSecretLen,
  }
}
