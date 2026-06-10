# @deny-sh/langchain

Wrap a [deny.sh](https://deny.sh) vault entry as a LangChain v1 tool. The
credential resolves inside the tool boundary; only a narrowed DTO reaches the
model. Fail-closed leak sweep.

```bash
npm install @deny-sh/langchain @langchain/core
# plus your model provider + zod, e.g.
npm install @langchain/openai langchain zod
```

## Usage

```ts
import { createAgent } from 'langchain';
import { ChatOpenAI } from '@langchain/openai';
import { denyVaultTool } from '@deny-sh/langchain';
import { z } from 'zod';

const invoiceTool = denyVaultTool({
  label: 'stripe-prod',                 // or: id: 'item_abc' (skips the label scan)
  password: process.env.VAULT_PW!,      // server env, never the agent prompt
  name: 'get_invoice',
  description: 'Look up a Stripe invoice by id',
  schema: z.object({ id: z.string() }),
  use: async (stripeKey, { id }) => {
    const r = await fetch(`https://api.stripe.com/v1/invoices/${id}`, {
      headers: { Authorization: `Bearer ${stripeKey}` },
    });
    const body = await r.json();
    // narrowed DTO — never the raw key, never the raw upstream body
    return { id: body.id, amount_due: body.amount_due, status: body.status };
  },
});

const agent = createAgent({
  model: new ChatOpenAI({ model: 'gpt-4o' }),
  tools: [invoiceTool],
});
```

The Stripe key is resolved and consumed entirely inside `use()`. LangChain sees
the input args and the narrowed return string; the model provider sees the same.
The key never crosses any wire that isn't `deny.sh → your server → upstream`.

## Multi-tenant

Capture per-tenant context in a closure so there's no fallback to a shared key:

```ts
function toolsForTenant(tenantId: string, tenantPw: string, tenantApiKey: string) {
  return [
    denyVaultTool({
      label: 'stripe-prod',
      password: tenantPw,
      clientOptions: { apiKey: tenantApiKey },
      name: 'get_invoice',
      description: 'Look up an invoice for this tenant',
      schema: z.object({ id: z.string() }),
      use: async (key, { id }) => { /* ... narrowed DTO ... */ },
    }),
  ];
}
```

A leak of one tenant's vault password compromises that tenant only. The boundary
is cryptographic, not policy-based.

## Config

| Field | Required | Notes |
|-------|----------|-------|
| `label` / `id` | one of | vault entry label, or a stable item id |
| `password` | yes | vault wrap password (derives the decryption key) |
| `name`, `description`, `schema` | yes | standard LangChain tool fields |
| `use(secret, args)` | yes | privileged work; return a narrowed DTO |
| `clientOptions` | no | `{ apiKey, baseUrl, ... }` forwarded to `deny-sh/client` |
| `leakSweep` | no | default `true`; fail-closed scan of the returned DTO |

Apache-2.0. Part of [deny-sh-integrations](https://github.com/deny-sh-crypto/deny-sh-integrations).
