# 🚨 NEXT SESSION — START HERE

**PUBLISH MATRIX COMPLETE ✅ (2026-06-11).** All adapters live + fresh-install-smoke-verified on BOTH registries. Nothing left to publish here.

**npm (all 0.1.0, smoke-green incl. T3 zod4 case → zod 4.4.3):**
- `deny-sh-integrations-core`, `deny-sh-langchain`, `deny-sh-vercel-ai`, `deny-sh-openai-agents`
- (Packages renamed UNSCOPED per `55e3cc8` — `deny-sh-*`, NOT `@deny-sh/*`. The old scoped names never published; don't be fooled by a stale `npm view @deny-sh/*` 404.)

**PyPI (both 0.1.0, smoke-green):**
- `deny-sh-langchain` → https://pypi.org/project/deny-sh-langchain/0.1.0/
- `deny-sh-openai-agents` → https://pypi.org/project/deny-sh-openai-agents/0.1.0/

**Site reflects it** (deniable-crypto `de8af466`): new `/integrations/openai-agents` page + index card + framework count 8→9 across landing/integrations/docs/whitepaper + sitemap. Dead `deny-integrations` repo link fixed → `deny-sh-integrations`.

**STILL OPEN (carry to broader site audit, not this repo):**
- Alex's EOD goal: sweep ALL website surfaces to reflect every recent feature (browser Honey Mode, /verify proof band, compliance-pack, framework adapters). Today covered integrations + landing/docs/whitepaper framework-count ONLY. NOT swept: pricing, /agents, /enterprise, /verify, /compare, blog, individual feature pages.
- **deny-rs republish** (branch-oracle fix) — human-gated, separate.
- **Server deploy** (SSRF + compliance-pack + rate-limits + browser honey list, core `3ced3025`) — human-gated, separate.

**Future adapter version bumps**: project-scoped PyPI token is enough now (both projects exist). Account-scoped token used for first publish was revoked.

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
