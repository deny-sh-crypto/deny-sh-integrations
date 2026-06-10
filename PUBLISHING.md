# Publishing (registry release runbook)

Packages are built + tested + smoke-verified but **not yet published to npm/PyPI**.
Registry publish needs the `@deny-sh` npm org + PyPI `deny-sh-langchain` project +
credentials, so it is a deliberate human-gated step (Alex).

## Order

`@deny-sh/integrations-core` MUST publish first (the adapters depend on it).

## Whitelist gate (automatic, do not skip)

Each package's `prepublishOnly` runs `scripts/prepublish-verify-npm.mjs`, which
packs the real tarball and resolves the full relative-import graph against
package.json `files`. `npm publish` ABORTS if any imported `.js` is missing from
the tarball. This is THE fix for the recurring files-whitelist republish bug
(core SDK 2.0.6 decoy-engine, 2.2.1 honey.js). It runs automatically; you do not
invoke it by hand. A red `✗ ... NOT in the tarball` means: fix the `files` array,
do NOT publish.

## npm (core → langchain-js → vercel-ai)

```bash
NODE_ENV=development npm install --include=dev
npm run build
npm run typecheck && npm test          # 45/45 green

# 1. core  (prepublishOnly gate runs build + whitelist verify automatically)
cd packages/core && npm publish --access public
# 2. adapters (after core is live on npm)
cd ../langchain-js && npm publish --access public
cd ../vercel-ai && npm publish --access public
cd ../openai-agents && npm publish --access public
```


Requires an `@deny-sh` npm org and a member/automation token with publish rights.

## PyPI (langchain-py, openai-agents-py)

```bash
cd packages/langchain-py
python -m build           # wheel + sdist
twine upload dist/*       # needs the deny-sh-langchain PyPI project + token

cd ../openai-agents-py
python -m build           # wheel + sdist
twine upload dist/*       # needs the deny-sh-openai-agents PyPI project + token
```

## Mandatory post-publish fresh-install smoke (per package)

`npm pack --dry-run` is NOT sufficient (the core SDK's honey.js whitelist bug
proved this). Always install the published artifact in a scratch dir and import.

```bash
cd /tmp && rm -rf smoke && mkdir smoke && cd smoke && npm init -y
npm i @deny-sh/langchain @langchain/core zod
node -e 'import("@deny-sh/langchain").then(m=>console.log(Object.keys(m)))'
# @openai/agents peers zod v4 (NOT v3 like the LangChain/Vercel adapters)
npm i @deny-sh/openai-agents @openai/agents zod
node -e 'import("@deny-sh/openai-agents").then(m=>console.log(Object.keys(m)))'
```

```bash
cd /tmp && python3 -m venv s && source s/bin/activate
pip install deny-sh-langchain langchain-core pydantic
python -c "import deny_sh_langchain as m; print([x for x in dir(m) if not x.startswith('_')])"
pip install deny-sh-openai-agents openai-agents pydantic
python -c "import deny_sh_openai_agents as m; print([x for x in dir(m) if not x.startswith('_')])"
```

Expected exports: `denyVaultTool`/`deny_vault_tool`, `createVaultResolver`/
`create_vault_resolver`, `isNarrowed`/`is_narrowed`, `DenyToolError`, `DenyLeakError`.

## After publish: site hygiene

The integration pages (`web/integrations/*.html` in the core repo) currently show
the inline `vault_get`/`vaultGet` pattern using the published **core** SDK, which
is honest and works today. Once these convenience packages are live, optionally
add a `npm i @deny-sh/<framework>` / `pip install deny-sh-<framework>` snippet to
the built pages (langchain, vercel-ai-sdk) as the recommended path. Do NOT add a
package install snippet to a page whose package is not yet published.

## v1.1 wave (same core, mechanical)

LlamaIndex, CrewAI, Pydantic-AI, AutoGen, n8n. Each wraps `createVaultResolver` /
`create_vault_resolver`. Add a "coming soon" badge to any framework page that
gains a package install snippet before its package ships.

(OpenAI Agents SDK shipped pre-launch as the T3 adapter:
`@deny-sh/openai-agents` + `deny-sh-openai-agents`.)
