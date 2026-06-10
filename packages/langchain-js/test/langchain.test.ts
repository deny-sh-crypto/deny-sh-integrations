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

test('builds a LangChain tool with the right name/description', () => {
  const t = denyVaultTool({
    label: 'stripe-prod',
    password: 'pw',
    name: 'get_invoice',
    description: 'Look up a Stripe invoice by id',
    schema: z.object({ id: z.string() }),
    client: mockClient(),
    use: () => ({ ok: true }),
  });
  assert.equal((t as { name: string }).name, 'get_invoice');
  assert.equal((t as { description: string }).description, 'Look up a Stripe invoice by id');
  assert.equal(typeof (t as { invoke: unknown }).invoke, 'function');
});

test('invoking the tool resolves the secret in-boundary and returns narrowed JSON', async () => {
  const client = mockClient();
  let sawSecret: string | undefined;
  const t = denyVaultTool<{ id: string }, { id: string; status: string }>({
    label: 'stripe-prod',
    password: 'VAULT_PW',
    name: 'get_invoice',
    description: 'd',
    schema: z.object({ id: z.string() }),
    client,
    use: (secret, { id }) => {
      sawSecret = secret;
      return { id, status: 'paid' };
    },
  });
  const out = await (t as { invoke: (a: unknown) => Promise<string> }).invoke({ id: 'in_1' });
  assert.equal(sawSecret, FAKE_SECRET, 'use() got the decrypted secret');
  const parsed = JSON.parse(out);
  assert.deepEqual(parsed, { id: 'in_1', status: 'paid' });
  assert.ok(!out.includes(FAKE_SECRET), 'tool output must not contain the raw secret');
  assert.deepEqual(client.calls[0], { label: 'stripe-prod', password: 'VAULT_PW', opts: undefined });
});

test('FAIL CLOSED: a tool that returns the raw secret throws DenyLeakError on invoke', async () => {
  const t = denyVaultTool({
    label: 'k',
    password: 'pw',
    name: 'leaky',
    description: 'd',
    schema: z.object({ id: z.string() }),
    client: mockClient(),
    use: (secret) => ({ key: secret }),
  });
  await assert.rejects(
    () => (t as { invoke: (a: unknown) => Promise<string> }).invoke({ id: 'x' }),
    DenyLeakError,
  );
});

test('schema validation rejects malformed args before decrypt (client never called)', async () => {
  const client = mockClient();
  const t = denyVaultTool({
    label: 'k',
    password: 'pw',
    name: 'strict',
    description: 'd',
    schema: z.object({ id: z.string() }),
    client,
    use: () => ({ ok: true }),
  });
  await assert.rejects(() =>
    (t as { invoke: (a: unknown) => Promise<string> }).invoke({ id: 123 } as unknown as object),
  );
  assert.equal(client.calls.length, 0, 'decrypt must not run on invalid args');
});

test('id path threads the id (not a label) to the client', async () => {
  const client = mockClient();
  const t = denyVaultTool({
    id: 'item_abc',
    password: 'pw',
    name: 'byid',
    description: 'd',
    schema: z.object({ id: z.string() }),
    client,
    use: () => ({ ok: true }),
  });
  await (t as { invoke: (a: unknown) => Promise<string> }).invoke({ id: 'x' });
  assert.deepEqual(client.calls[0], { id: 'item_abc', password: 'pw', opts: undefined });
});
