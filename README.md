# opencode-vibeguard-v2

VibeGuard for OpenCode **V2**. Ported from the V1 plugin
[`opencode-vibeguard@0.1.0`](https://github.com/inkdust2021/opencode-vibeguard) (MIT, by inkdust2021).

Replaces configured sensitive strings with `__VG_<CATEGORY>_<hash12>__` placeholders **before requests
reach the LLM provider**, and restores them **before local tools execute** so tools always run with
real values.

## Install

```sh
# from GitHub (this fork, hardening branch)
opencode plugin add github:famewolf/opencode-vibeguard-v2

# from a local checkout
opencode plugin add /absolute/path/to/opencode-vibeguard-v2

# or via config
# "plugins": ["github:famewolf/opencode-vibeguard-v2"]
```

OpenCode V2 also auto-discovers global plugins from `~/.config/opencode/plugins/`; dropping this
directory there works too.

## Setup (5 minutes)

1. **Create a config.** Copy `vibeguard.config.json.example` to one of the lookup
   locations (`./vibeguard.config.json`, `./.opencode/vibeguard.config.json`, or
   the global `~/.config/opencode/vibeguard.config.json`) and set
   `"enabled": true`. Without a config the plugin is a no-op and logs a loud
   `DISABLED` error — check for that line on first run.
2. **Register your secret files.** Either one flag to track the cc-safety-net
   deny list (recommended, see below):
   ```json
   { "patterns": { "import_deny_paths": true } }
   ```
   or point at files directly:
   ```json
   { "patterns": { "protected_files": ["/home/user/.config/myapp/token"] } }
   ```
3. **Verify.** Set `"debug": true`, restart opencode, and look for
   `[opencode-vibeguard] protected files: N secret(s) from M file(s)` (counts
   only, never values) plus `pre-request redaction: N fragment(s)` on the first
   request that touches a secret.

## Recommended pairing: cc-safety-net

This plugin and [cc-safety-net](https://github.com/kenryu42/cc-safety-net) solve
opposite halves of the same leak. cc-safety-net stops the model from *reading*
sensitive files into the session; vibeguard stops anything already in the
session from *reaching the provider*. Either one alone leaves a gap — tokens
have leaked into sessions past cc-safety-net, and vibeguard alone cannot stop a
`read` of a secret file. Run both.

Manage the shared deny list with the bundled script (Node 20+, no dependencies):

```sh
# first time without cc-safety-net: create an empty policy file
node scripts/add-deny-path.mjs --init
# register a file (absolute paths only, idempotent)
node scripts/add-deny-path.mjs /absolute/path/to/secret-file
# show what is registered
node scripts/add-deny-path.mjs list
# custom policy location (mirrors the deny_policy config option)
node scripts/add-deny-path.mjs --policy /path/to/policy.json list
```

With `"import_deny_paths": true`, every registered file is re-read at each
plugin setup, so no re-export step is needed when the list changes.

## How it maps to the V2 plugin API

| V1 hook | V2 equivalent |
| --- | --- |
| `experimental.chat.messages.transform` | `ctx.session.hook("context" \| "compaction" \| "generate" \| "title")` |
| `tool.execute.before` | `ctx.tool.hook("execute.before")` |
| `experimental.text.complete` | ❌ not available in OpenCode 2.0.1 (see below) |

The port redacts `text` / `reasoning` / `compaction` parts, `tool-call` inputs, `tool-result`
outputs, and system parts (`event.system[].text`, which V1 could not see).

## Known limitation: placeholders in the transcript

V2 has no working response-side restore hook on OpenCode 2.0.1. If the model echoes a placeholder in
assistant text, the local transcript shows the placeholder. Tested and rejected:

| Approach | Result |
| --- | --- |
| `ctx.aisdk.hook("language", ...)` wrapping `LanguageModelV3` | Hooks register (`ctx.aisdk` exists) but are never triggered by the runtime |
| `ctx.session.hook("http.response", ...)` replacing the response body | Hook fires, but the replaced `event.response` is discarded: the trigger wraps object fields in immer drafts and resets the field with `finishDraft(draft)` after hooks |
| `session.text.ended` event | Read-only, cannot write back |

What still works: the provider never sees plaintext, and tools always receive restored values
(including `write` / `edit` / `bash`). Only the rendered/stored assistant text keeps placeholders.

Practical asymmetry:

- Tool **results** and files contain real values (they are stored as produced, e.g. a `read` or
  `browser.tabs.list` result shows real IDs).
- Model-authored **text** and **tool-call arguments** keep placeholders in the transcript, because
  OpenCode persists the model output before the `execute.before` restore runs and offers no API to
  rewrite stored messages. The execution itself still uses the restored values.

Wanted? File an upstream feature request for a text-mutation hook (the V1
`experimental.text.complete` equivalent).

## Config

Config lookup order (first match wins):

1. `OPENCODE_VIBEGUARD_CONFIG` env var
2. `<location>/vibeguard.config.json`
3. `<location>/.opencode/vibeguard.config.json`
4. `~/.config/opencode/vibeguard.config.json`

Plugin instances are location-scoped, so project configs are found before the global one. The plugin
is a no-op when no config is found or `enabled=false`. See `vibeguard.config.json.example`.

Invalid regex rules are skipped at setup with an error log instead of breaking every model request.

Builtin patterns: `email`, `china_phone`, `china_id`, `uuid`, `ipv4`, `mac`,
plus the `secrets` group (on by default): OpenAI/Anthropic/Google keys, GitHub
`gh[pousr]_` + `github_pat_`, GitLab, AWS access/secret, Slack tokens + webhooks,
Stripe, npm/PyPI, private-key headers, password-bearing database URLs, and generic
`password = ...` / `api_key: ...` assignments. Omit `builtin` to get `secrets`;
pass an explicit list (even `[]`) to opt out. `ipv4` validates 0-255 per octet
(`999.999.999.999` is left alone).

The plugin is a no-op when no config is found or `enabled=false`, and now logs a
loud `DISABLED` error in that case instead of staying silent.

## Adding your own content

Four ways, from simplest to most explicit. They compose: everything found by any
method is protected.

**1. Do nothing (recommended start).** The `secrets` builtin group is on by
default and covers the common token shapes (OpenAI, Anthropic, Google, GitHub,
GitLab, AWS, Slack, Stripe, npm/PyPI, private keys, password-bearing database
URLs, generic `password = ...` assignments). If you never set `builtin`, you
already have it. This catches secret *shapes* but not arbitrary values like a
bare hex token with no prefix.

**2. Track the cc-safety-net deny list.** One flag imports every file registered
with the `add-deny-path` tool (`~/.cc-safety-net/policy.json`):

```json
{ "patterns": { "import_deny_paths": true } }
```

Flow: `add-deny-path /absolute/path/to/secret-file` once, restart opencode, and
that file's contents are redacted front-side from then on. Override the policy
location with `"deny_policy": "/path/to/policy.json"`. To add a single file
without the deny list, or to include files the deny list does not cover, use
`protected_files`:

```json
{ "patterns": { "protected_files": ["/home/user/.config/myapp/token"] } }
```

Both are read at plugin setup (64KB cap per file). Supported layouts: a file
holding one bare token, `KEY=VALUE` lines (`.env`, shell exports, quoting
stripped), and `KEY: VALUE` lines (yaml). Blank lines, `#` comments, short
values (under `min_secret_len`, default 8), and placeholder words (`changeme`,
`xxx`, ...) are skipped. Unreadable files log a warning with the path and
reason, never a crash, and values are never written to logs or stdout.

**3. Static keyword export.** Prefer live tracking (option 2), but if you want
values pinned in the config, export them once:

```sh
node scripts/sync-deny-paths.mjs --out vibeguard.keywords.json
# paste the keywords array into vibeguard.config.json under patterns.keywords
```

The script prints counts only, never secret values. Re-run it whenever the deny
list changes; the live `import_deny_paths` option avoids this entirely.

**4. Hand-written keywords and regex.** For one-off values and in-house formats:

```json
{
  "patterns": {
    "keywords": [{ "value": "my-api-key-123", "category": "API_KEY" }],
    "regex": [{ "pattern": "my-internal-token-[0-9]+", "category": "INTERNAL_TOKEN" }],
    "exclude": ["safe-to-show.example.com"]
  }
}
```

Keywords are literal case-sensitive matches; regex entries accept an optional
`"flags"` string. `category` becomes part of the placeholder
(`__VG_<CATEGORY>_<hash>__`) — keep it descriptive so transcript placeholders
stay readable. Invalid regexes are skipped with an error log at setup.

Check what is active with `"debug": true` (or `OPENCODE_VIBEGUARD_DEBUG=1`): setup
logs the config source plus `protected files: N secret(s) from M file(s)` —
counts only.

Debug: set `"debug": true` in the config or `OPENCODE_VIBEGUARD_DEBUG=1`. Debug writes load
diagnostics to `<tmpdir>/opencode-vibeguard-trace.log`.

## Protecting file contents (tokens, .env, yaml)

Point the plugin at files whose contents must never reach the provider:

```json
{
  "patterns": {
    "protected_files": ["/home/user/.config/myapp/token", "/home/user/project/.env"],
    "min_secret_len": 8,
    "import_deny_paths": true
  }
}
```

Each file is read at setup (64KB cap) and every `KEY=VALUE` / `KEY: VALUE` value
or single-token line becomes a keyword. Unreadable files log a warning, never a
crash, and values are never logged.

To ingest your cc-safety-net deny list, either set `"import_deny_paths": true`
(reads `~/.cc-safety-net/policy.json`, override with `"deny_policy"`), or export
a static snippet:

```sh
node scripts/sync-deny-paths.mjs --out vibeguard.keywords.json
# paste the keywords array into vibeguard.config.json under patterns.keywords
```

The script prints counts only, never secret values.

## Reliability notes

- Sessions are bounded (`session.max_sessions`, default 50, LRU-evicted).
- Inputs over `patterns.max_text_chars` (default 500000) are scanned up to the
  cap and flagged; the tail passes through and a debug warning is logged.
- `redactDeep`/`restoreDeep` walk `Array`, plain objects, `Map`, and `Set`.

## Development

```sh
npm test
```

Requires Node 20+. Zero runtime dependencies; the plugin only uses Node builtins.

## License

MIT. Original plugin and VibeGuard placeholder format by inkdust2021.
