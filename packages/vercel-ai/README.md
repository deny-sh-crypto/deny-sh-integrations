# @deny-sh/vercel-ai

Wrap a [deny.sh](https://deny.sh) vault entry as a Vercel AI SDK tool. The
credential resolves inside `execute()`; only a narrowed DTO reaches the model.
Fail-closed leak sweep.

Requires AI SDK v5+.

```bash
npm install @deny-sh/vercel-ai ai
# plus your model provider + zod, e.g.
npm install @ai-sdk/openai zod
```

## Usage

```ts
// app/api/agent/route.ts
import { generateText, stepCountIs } from 'ai';
import { openai } from '@ai-sdk/openai';
import { denyVaultTool } from '@deny-sh/vercel-ai';
import { z } from 'zod';

const getInvoice = denyVaultTool({
  label: 'stripe-prod',                 // or: id: 'item_abc' (skips the label scan)
  password: process.env.VAULT_PW!,      // server env, never the prompt
  description: 'Look up a Stripe invoice by id',
  inputSchema: z.object({ id: z.string() }),
  use: async (stripeKey, { id }) => {
    const r = await fetch(`https://api.stripe.com/v1/invoices/${id}`, {
      headers: { Authorization: `Bearer ${stripeKey}` },
    });
    if (!r.ok) return { error: 'invoice_lookup_failed', status: r.status };
    const body = await r.json();
    // narrowed DTO — never the raw key, never the raw upstream body
    return { id: body.id, amount_due: body.amount_due, status: body.status };
  },
});

export async function POST(req: Request) {
  const { messages } = await req.json();
  const { text } = await generateText({
    model: openai('gpt-4o'),
    tools: { getInvoice },
    messages,
    stopWhen: stepCountIs(5),
  });
  return Response.json({ text });
}
```

`generateText` sends the prompt + tool schema; the model emits the tool call;
`execute` resolves the key, calls upstream, and returns the narrowed DTO. The
model never sees the Stripe key at any point in the loop.

## Multi-tenant

```ts
const getInvoiceFor = (tenantId: string, tenantPw: string) =>
  denyVaultTool({
    label: 'stripe-prod',
    password: tenantPw,
    clientOptions: { apiKey: tenantKeyFor(tenantId) },
    description: 'Look up an invoice for the current tenant',
    inputSchema: z.object({ id: z.string() }),
    use: async (key, { id }) => { /* ... narrowed DTO ... */ },
  });
```

Two tenants holding the same product cannot decrypt each other's entry. The
deniability boundary is cryptographic, not policy-based.

## Config

| Field | Required | Notes |
|-------|----------|-------|
| `label` / `id` | one of | vault entry label, or a stable item id |
| `password` | yes | vault wrap password (derives the decryption key) |
| `description`, `inputSchema` | yes | standard AI SDK tool fields |
| `use(secret, args)` | yes | privileged work; return a narrowed DTO |
| `clientOptions` | no | `{ apiKey, baseUrl, ... }` forwarded to `deny-sh/client` |
| `leakSweep` | no | default `true`; fail-closed scan of the returned DTO |

Apache-2.0. Part of [deny-sh-integrations](https://github.com/deny-sh-crypto/deny-sh-integrations).
