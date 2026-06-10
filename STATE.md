# 🚨 NEXT SESSION — START HERE

**PUBLISH the adapters** (Alex bringing a phone hotspot to the desktop, before he leaves for the office). All built, tested, gated GREEN — nothing left to build, this is a publish + post-publish-smoke job.

Publish order + exact commands + smokes: **`PUBLISHING.md`** (authoritative).

1. **npm** (strict order, core first): `@deny-sh/integrations-core` → `@deny-sh/langchain` → `@deny-sh/vercel-ai` → `@deny-sh/openai-agents`. Each `prepublishOnly` auto-runs the whitelist gate (can't skip). Needs `@deny-sh` npm org + publish token.
2. **PyPI**: `deny-sh-langchain` + `deny-sh-openai-agents` (`python -m build` + `twine upload dist/*`). Needs the PyPI projects + tokens.
3. **Post-publish fresh-install smoke per package** (mandatory, PUBLISHING.md). `npm pack --dry-run` is NOT sufficient.
   - ⚠️ T3 gotcha: `@deny-sh/openai-agents` peers **zod v4** (the LangChain/Vercel adapters use zod v3). The smoke must `npm i @deny-sh/openai-agents @openai/agents zod` (resolves zod4).
4. After live: optionally add `npm i`/`pip install` snippets to the integration pages in the **core repo** (`web/integrations/*.html`) — but ONLY for a package that is actually published. Never ship a dead install command.

Separately (also from this morning's audit, human-gated):
- **deny-rs republish** (branch-oracle fix).
- **Server deploy** (normal): SSRF + compliance-pack + rate-limits + browser honey list (core commit `3ced3025`).

Then Alex's EOD goal: sweep website copy + whitepaper + docs to reflect all the new features (browser Honey Mode, /verify proof band, compliance-pack, + the 3 framework adapters).

<!-- archived-plan-below -->

## Repo state (2026-06-10 08:52 BST)

Monorepo `deny-sh-integrations` (master, origin `deny-sh-crypto/deny-sh-integrations`). Public-intent, currently pre-publish.

**Packages (all v0.1.0, none published yet):**
- `packages/core` → `@deny-sh/integrations-core` — framework-agnostic `createVaultResolver` + fail-closed leak sweep. The shared security core; every adapter wraps it and adds NOTHING to the security model.
- `packages/langchain-js` → `@deny-sh/langchain` (T1, zod3 / @langchain/core peer)
- `packages/langchain-py` → `deny-sh-langchain` (T1)
- `packages/vercel-ai` → `@deny-sh/vercel-ai` (T2, zod3 / ai v5 peer)
- `packages/openai-agents` → `@deny-sh/openai-agents` (T3, **zod4** / @openai/agents peer) — NEW `10e22ff`
- `packages/openai-agents-py` → `deny-sh-openai-agents` (T3) — NEW `10e22ff`

**Contract (all adapters identical):** vault-entry-as-tool. Credential resolves + is consumed inside the tool boundary via `use(secret, args)`; only a narrowed DTO returns to the model; a fail-closed leak sweep throws if the raw secret appears anywhere in the DTO. The deniability boundary is cryptographic, not policy.

**T3 design note:** `@openai/agents` `tool()` default error handler swallows thrown errors into a self-heal string. The TS adapter sets `errorFunction: null` so the (already secret-scrubbed) DenyToolError/DenyLeakError propagate fail-closed, matching the other adapters. The Python adapter builds `agents.FunctionTool` directly; `on_invoke_tool(ctx, json)` validates args through the pydantic `args_schema` then runs the resolver.

**Gates (run before any publish):**
- TS: `NODE_ENV=development npm install --include=dev && npm run build && npm run typecheck && npm test` → 36 tests, 0 fail.
- Per-package whitelist gate: `node scripts/prepublish-verify-npm.mjs packages/<pkg>` → "safe to publish" (also auto-runs in `prepublishOnly`).
- Py: `PYTHONPATH=src python -m pytest tests/ -q` in each py package (needs `pytest pydantic` + the SDK for the integration tests; langchain-py 22/22, openai-agents-py 22/22).

**Build env quirk:** clawdbot shell exports `NODE_ENV=production` → omits devDeps. Always prefix installs/builds/tests with `NODE_ENV=development`.

**Not built (v1.1 fast-follow, same core, mechanical):** LlamaIndex, CrewAI, Pydantic-AI, AutoGen, n8n.
