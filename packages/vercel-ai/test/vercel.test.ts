import { test } from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { denyVaultTool, DenyLeakError, type VaultClient } from '../src/index.js';

const FAKE_SECRET = 'sk_test_DENYFAKE_0000_not_a_real_key';

function mockClient(secret = FAKE_SECRET): VaultClient & { calls: unknown[] } {
  const calls: unknown[] = [];
  return {
    calls,
    async vaultGet(label, password, opts) {
      calls.push({ label, password, opts });
      return secret;
    },
    async vaultGetById(id, password, opts) {
      calls.push({ id, password, opts });
      return secret;
    },
  };
}

// The AI SDK tool object exposes `execute` (and `inputSchema`). We test that
// surface directly, which is what generateText calls under the hood.
type AiTool = { description: string; inputSchema: unknown; execute: (args: unknown, opts?: unknown) => Promise<unknown> };

test('builds an AI SDK tool with description + inputSchema + execute', () => {
  const t = denyVaultTool({
    label: 'stripe-prod',
    password: 'pw',
    description: 'Look up a Stripe invoice by id',
    inputSchema: z.object({ id: z.string() }),
    client: mockClient(),
    use: () => ({ ok: true }),
  }) as unknown as AiTool;
  assert.equal(t.description, 'Look up a Stripe invoice by id');
  assert.ok(t.inputSchema);
  assert.equal(typeof t.execute, 'function');
});

test('execute resolves the secret in-boundary and returns the narrowed DTO object', async () => {
  const client = mockClient();
  let sawSecret: string | undefined;
  const t = denyVaultTool<{ id: string }, { id: string; status: string }>({
    label: 'stripe-prod',
    password: 'VAULT_PW',
    description: 'd',
    inputSchema: z.object({ id: z.string() }),
    client,
    use: (secret, { id }) => {
      sawSecret = secret;
      return { id, status: 'paid' };
    },
  }) as unknown as AiTool;
  const out = await t.execute({ id: 'in_1' }, {});
  assert.equal(sawSecret, FAKE_SECRET);
  assert.deepEqual(out, { id: 'in_1', status: 'paid' });
  assert.ok(!JSON.stringify(out).includes(FAKE_SECRET));
  assert.deepEqual(client.calls[0], { label: 'stripe-prod', password: 'VAULT_PW', opts: undefined });
});

test('FAIL CLOSED: execute throws DenyLeakError when the DTO contains the raw secret', async () => {
  const t = denyVaultTool({
    label: 'k',
    password: 'pw',
    description: 'd',
    inputSchema: z.object({ id: z.string() }),
    client: mockClient(),
    use: (secret) => ({ key: secret }),
  }) as unknown as AiTool;
  await assert.rejects(() => t.execute({ id: 'x' }, {}), DenyLeakError);
});

test('clientOptions (per-tenant apiKey) are forwarded to the client', async () => {
  const client = mockClient();
  const t = denyVaultTool({
    label: 'stripe-prod',
    password: 'tenant_pw',
    clientOptions: { apiKey: 'cs_tenant_42' },
    description: 'd',
    inputSchema: z.object({ id: z.string() }),
    client,
    use: () => ({ ok: true }),
  }) as unknown as AiTool;
  await t.execute({ id: 'x' }, {});
  assert.deepEqual(client.calls[0], {
    label: 'stripe-prod',
    password: 'tenant_pw',
    opts: { apiKey: 'cs_tenant_42' },
  });
});
