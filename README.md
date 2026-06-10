# deny.sh integrations

Drop-in credential isolation for AI agent frameworks.

Wrap a [deny.sh](https://deny.sh) managed-vault entry as a framework tool. The
credential is resolved and consumed **inside the tool boundary**, server-side,
and only a narrowed DTO is returned to the agent. The raw secret never enters
the model's context window. A fail-closed leak sweep guarantees it.

This is the same pattern the deny.sh integration pages already show by hand,
packaged so you skip the boilerplate.

## Packages

| Package | Framework | Install |
|---------|-----------|---------|
| [`@deny-sh/langchain`](packages/langchain-js) | LangChain v1 (JS/TS) | `npm i @deny-sh/langchain @langchain/core` |
| [`@deny-sh/vercel-ai`](packages/vercel-ai) | Vercel AI SDK (v5) | `npm i @deny-sh/vercel-ai ai` |
| [`@deny-sh/openai-agents`](packages/openai-agents) | OpenAI Agents SDK (JS/TS) | `npm i @deny-sh/openai-agents @openai/agents` |
| [`deny-sh-langchain`](packages/langchain-py) | LangChain v1 (Python) | `pip install deny-sh-langchain` |
| [`deny-sh-openai-agents`](packages/openai-agents-py) | OpenAI Agents SDK (Python) | `pip install deny-sh-openai-agents` |
| [`@deny-sh/integrations-core`](packages/core) | framework-agnostic core | (dependency of the above) |

More frameworks (LlamaIndex, CrewAI, Pydantic-AI, AutoGen, n8n, OpenAI Agents
SDK) follow on the same core. Track them on the
[integrations index](https://deny.sh/integrations).

## The shape

```ts
import { denyVaultTool } from '@deny-sh/vercel-ai';
import { z } from 'zod';

const getInvoice = denyVaultTool({
  label: 'stripe-prod',                 // vault entry label
  password: process.env.VAULT_PW!,      // vault wrap password (server env, never the prompt)
  description: 'Look up a Stripe invoice by id',
  inputSchema: z.object({ id: z.string() }),
  use: async (stripeKey, { id }) => {
    // stripeKey exists only inside this closure, server-side
    const r = await fetch(`https://api.stripe.com/v1/invoices/${id}`, {
      headers: { Authorization: `Bearer ${stripeKey}` },
    });
    const body = await r.json();
    // return a narrowed DTO — never the raw key, never the raw upstream body
    return { id: body.id, amount_due: body.amount_due, status: body.status };
  },
});
```

The model sees the tool schema and the narrowed DTO. It never sees the Stripe
key. A successful prompt-injection that says "print the key" returns an apology,
because the key was never in the context window.

## Why a fail-closed leak sweep

`use()` is supposed to return a narrowed DTO. If a returned value contains the
raw credential anywhere (string, nested object, array, Map/Set, even an object
key), the resolver **throws and returns nothing**. The secret never crosses back
into the framework, and therefore never into the model. Opt out with
`leakSweep: false` only if you have an independent guarantee.

## Security model

- The deny.sh vault client (`deny-sh/client`) derives the AES-256 key locally
  from your wrap password; the server never sees the plaintext credential or the
  password.
- Per-tenant isolation is cryptographic: pass a per-tenant `clientOptions.apiKey`
  and password, and one tenant cannot decrypt another's entry.
- Vault fetch errors and `use()` exceptions are scrubbed of the secret/password
  before they surface as tool errors.

## Development

```bash
NODE_ENV=development npm install --include=dev
npm run build      # build all packages
npm test           # test all packages
```

Apache-2.0.
