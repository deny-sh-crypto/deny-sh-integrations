# @deny-sh/openai-agents

Wrap a [deny.sh](https://deny.sh) vault entry as an [OpenAI Agents SDK](https://openai.github.io/openai-agents-js/) tool. The
credential resolves inside `execute()`; only a narrowed DTO reaches the model.
Fail-closed leak sweep.

```bash
npm install @deny-sh/openai-agents @openai/agents
# plus zod (peered by @openai/agents v4)
npm install zod
```

## Usage

```ts
import { Agent, run } from '@openai/agents';
import { denyVaultTool } from '@deny-sh/openai-agents';
import { z } from 'zod';

const getInvoice = denyVaultTool({
  label: 'stripe-prod',                 // or: id: 'item_abc' (skips the label scan)
  password: process.env.VAULT_PW!,      // server env, never the prompt
  name: 'get_invoice',
  description: 'Look up a Stripe invoice by id',
  parameters: z.object({ id: z.string() }),
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

const agent = new Agent({
  name: 'Billing',
  instructions: 'Help the user with their invoices.',
  tools: [getInvoice],
});

const result = await run(agent, 'What is the status of invoice in_1?');
console.log(result.finalOutput);
```

The model emits the tool call; `execute` resolves the key, calls upstream, and
returns the narrowed DTO. The model never sees the Stripe key at any point in
the loop. If `use()` ever returns the raw secret, the leak sweep throws
(`DenyLeakError`) and the secret never crosses back into the model context.

## Multi-tenant

```ts
const getInvoiceFor = (tenantId: string, tenantPw: string) =>
  denyVaultTool({
    label: 'stripe-prod',
    password: tenantPw,
    clientOptions: { apiKey: tenantKeyFor(tenantId) },
    name: 'get_invoice',
    description: 'Look up an invoice for the current tenant',
    parameters: z.object({ id: z.string() }),
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
| `name`, `description`, `parameters` | yes | standard Agents SDK tool fields |
| `use(secret, args)` | yes | privileged work; return a narrowed DTO |
| `clientOptions` | no | `{ apiKey, baseUrl, ... }` forwarded to `deny-sh/client` |
| `leakSweep` | no | default `true`; fail-closed scan of the returned DTO |

Apache-2.0. Part of [deny-sh-integrations](https://github.com/deny-sh-crypto/deny-sh-integrations).
