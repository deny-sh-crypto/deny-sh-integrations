# deny-sh-integrations-core

The framework-agnostic security core behind every [deny.sh](https://deny.sh)
agent-framework adapter. You normally don't use this directly: install
[`deny-sh-langchain`](https://www.npmjs.com/package/deny-sh-langchain) or
[`deny-sh-vercel-ai`](https://www.npmjs.com/package/deny-sh-vercel-ai) instead.

It exposes one primitive, `createVaultResolver`, which:

1. Resolves a credential from the deny.sh managed vault and decrypts it
   server-side, inside a closure.
2. Runs your `use(secret, args)` callback (the only place the plaintext exists).
3. **Fail-closed leak sweeps** the returned DTO: if the raw secret appears
   anywhere in it (string, nested object/array, Map/Set, object key), the
   resolver throws and returns nothing. The secret never crosses the boundary.

```ts
import { createVaultResolver } from 'deny-sh-integrations-core';

const resolve = createVaultResolver({
  label: 'stripe-prod',
  password: process.env.VAULT_PW!,
  use: async (secret, args) => ({ /* narrowed DTO */ }),
});

const dto = await resolve({ id: 'in_123' }); // throws DenyLeakError if dto contains `secret`
```

## API

- `createVaultResolver(config)` → `(args) => Promise<DTO>`
- `isNarrowed(value, secret)` → `boolean` (the sweep predicate)
- `DenyToolError` — vault fetch / `use()` failure, secret-scrubbed
- `DenyLeakError` — fail-closed leak sweep tripped

Config: `{ label | id, password, use, clientOptions?, leakSweep?, client? }`.
Inject `client` (a `{ vaultGet, vaultGetById }`) to mock the network in tests.

Apache-2.0. Part of [deny-sh-integrations](https://github.com/deny-sh-crypto/deny-sh-integrations).
