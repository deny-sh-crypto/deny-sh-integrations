import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createVaultResolver,
  isNarrowed,
  DenyToolError,
  DenyLeakError,
  type VaultClient,
} from '../src/index.js';

// A fake secret that is obviously not a real key (scanner-safe).
const FAKE_SECRET = 'sk_test_DENYFAKE_0000_not_a_real_key';

function mockClient(secret = FAKE_SECRET): VaultClient & { getCalls: unknown[]; byIdCalls: unknown[] } {
  const getCalls: unknown[] = [];
  const byIdCalls: unknown[] = [];
  return {
    getCalls,
    byIdCalls,
    async vaultGet(label, password, opts) {
      getCalls.push({ label, password, opts });
      return secret;
    },
    async vaultGetById(id, password, opts) {
      byIdCalls.push({ id, password, opts });
      return secret;
    },
  };
}

test('resolves by label and threads label+password+opts to the client', async () => {
  const client = mockClient();
  const resolve = createVaultResolver<{ id: string }, { ok: boolean }>({
    label: 'stripe-prod',
    password: 'VAULT_PW',
    clientOptions: { apiKey: 'cs_test_x' },
    client,
    use: async (secret, args) => {
      assert.equal(secret, FAKE_SECRET, 'use() receives the decrypted secret');
      assert.equal(args.id, 'in_123');
      return { ok: true };
    },
  });
  const out = await resolve({ id: 'in_123' });
  assert.deepEqual(out, { ok: true });
  assert.equal(client.getCalls.length, 1);
  assert.equal(client.byIdCalls.length, 0);
  assert.deepEqual(client.getCalls[0], {
    label: 'stripe-prod',
    password: 'VAULT_PW',
    opts: { apiKey: 'cs_test_x' },
  });
});

test('resolves by id via vaultGetById (no label scan)', async () => {
  const client = mockClient();
  const resolve = createVaultResolver({
    id: 'item_abc',
    password: 'pw',
    client,
    use: () => ({ ok: true }),
  });
  await resolve({});
  assert.equal(client.byIdCalls.length, 1);
  assert.equal(client.getCalls.length, 0);
});

test('FAIL CLOSED: leak sweep throws when the raw secret is returned (string)', async () => {
  const resolve = createVaultResolver({
    label: 'k',
    password: 'pw',
    client: mockClient(),
    use: (secret) => `here is the key: ${secret}`,
  });
  await assert.rejects(() => resolve({}), (e: unknown) => {
    assert.ok(e instanceof DenyLeakError);
    assert.equal((e as DenyLeakError).code, 'deny_secret_leak');
    return true;
  });
});

test('FAIL CLOSED: leak sweep catches the secret nested deep in an object/array', async () => {
  const resolve = createVaultResolver({
    label: 'k',
    password: 'pw',
    client: mockClient(),
    use: (secret) => ({ a: { b: [{ c: ['ok', secret] }] } }),
  });
  await assert.rejects(() => resolve({}), DenyLeakError);
});

test('FAIL CLOSED: leak sweep catches the secret used as an object key', async () => {
  const resolve = createVaultResolver({
    label: 'k',
    password: 'pw',
    client: mockClient(),
    use: (secret) => ({ [secret]: 'value' }),
  });
  await assert.rejects(() => resolve({}), DenyLeakError);
});

test('FAIL CLOSED: leak sweep catches the secret in a Map and a Set', async () => {
  const r1 = createVaultResolver({
    label: 'k', password: 'pw', client: mockClient(),
    use: (secret) => new Map([['k', secret]]),
  });
  await assert.rejects(() => r1({}), DenyLeakError);
  const r2 = createVaultResolver({
    label: 'k', password: 'pw', client: mockClient(),
    use: (secret) => new Set(['ok', secret]),
  });
  await assert.rejects(() => r2({}), DenyLeakError);
});

test('a properly narrowed DTO passes the sweep', async () => {
  const resolve = createVaultResolver({
    label: 'k',
    password: 'pw',
    client: mockClient(),
    use: (_secret) => ({ id: 'in_123', status: 'paid', amount_due: 4200 }),
  });
  const out = await resolve({});
  assert.deepEqual(out, { id: 'in_123', status: 'paid', amount_due: 4200 });
});

test('leakSweep:false bypasses the sweep (opt-out honored)', async () => {
  const resolve = createVaultResolver({
    label: 'k',
    password: 'pw',
    client: mockClient(),
    leakSweep: false,
    use: (secret) => ({ leaked: secret }),
  });
  const out = await resolve({});
  assert.deepEqual(out, { leaked: FAKE_SECRET });
});

test('a thrown error from use() is scrubbed of the secret and re-coded', async () => {
  const resolve = createVaultResolver({
    label: 'k',
    password: 'pw',
    client: mockClient(),
    use: (secret) => {
      throw new Error(`upstream rejected token ${secret} loudly`);
    },
  });
  await assert.rejects(() => resolve({}), (e: unknown) => {
    assert.ok(e instanceof DenyToolError);
    assert.equal((e as DenyToolError).code, 'deny_use_failed');
    assert.ok(!(e as Error).message.includes(FAKE_SECRET), 'secret must be scrubbed from the error');
    assert.ok((e as Error).message.includes('[deny:redacted]'));
    return true;
  });
});

test('a vault fetch failure surfaces as DenyToolError, scrubbed of the password', async () => {
  const failing: VaultClient = {
    async vaultGet() {
      const e = new Error('boom for password hunter2') as Error & { code: string };
      e.code = 'vault_not_found';
      throw e;
    },
    async vaultGetById() {
      throw new Error('nope');
    },
  };
  const resolve = createVaultResolver({
    label: 'k',
    password: 'hunter2',
    client: failing,
    use: () => ({ ok: true }),
  });
  await assert.rejects(() => resolve({}), (e: unknown) => {
    assert.ok(e instanceof DenyToolError);
    assert.equal((e as DenyToolError).code, 'vault_not_found');
    assert.ok(!(e as Error).message.includes('hunter2'), 'password must be scrubbed');
    return true;
  });
});

test('config validation: requires label OR id (not neither, not both)', () => {
  assert.throws(
    () => createVaultResolver({ password: 'pw', client: mockClient(), use: () => ({}) }),
    DenyToolError,
  );
  assert.throws(
    () => createVaultResolver({ label: 'a', id: 'b', password: 'pw', client: mockClient(), use: () => ({}) }),
    DenyToolError,
  );
});

test('config validation: requires password and use()', () => {
  assert.throws(
    () => createVaultResolver({ label: 'a', password: '', client: mockClient(), use: () => ({}) } as never),
    DenyToolError,
  );
  assert.throws(
    () => createVaultResolver({ label: 'a', password: 'pw', client: mockClient() } as never),
    DenyToolError,
  );
});

test('isNarrowed helper matches the sweep semantics', () => {
  assert.equal(isNarrowed({ id: 'x' }, FAKE_SECRET), true);
  assert.equal(isNarrowed({ leaked: FAKE_SECRET }, FAKE_SECRET), false);
  assert.equal(isNarrowed(`prefix ${FAKE_SECRET}`, FAKE_SECRET), false);
});

// ─── Adversarial leak-sweep carriers (pre-publish wide audit 2026-06-10) ─────
// Each case hides the raw secret in a DTO shape the original sweep missed. The
// resolver MUST fail closed (DenyLeakError) for every one.

async function expectLeak(dto: unknown): Promise<void> {
  const resolve = createVaultResolver({
    label: 'k',
    password: 'pw',
    client: mockClient(),
    use: () => dto,
  });
  await assert.rejects(() => resolve({}), DenyLeakError);
}

test('leak sweep: secret behind a Symbol-keyed property', async () => {
  const sym = Symbol('hidden');
  await expectLeak({ ok: true, [sym]: FAKE_SECRET });
});

test('leak sweep: secret behind a non-enumerable property', async () => {
  const dto: Record<string, unknown> = { ok: true };
  Object.defineProperty(dto, 'hidden', { value: FAKE_SECRET, enumerable: false });
  await expectLeak(dto);
});

test('leak sweep: secret revealed by an own getter', async () => {
  const dto = {
    ok: true,
    get token() {
      return FAKE_SECRET;
    },
  };
  await expectLeak(dto);
});

test('leak sweep: secret revealed by a prototype-chain getter', async () => {
  class Carrier {
    ok = true;
    get token(): string {
      return FAKE_SECRET;
    }
  }
  await expectLeak(new Carrier());
});

test('leak sweep: secret bytes in a Buffer/Uint8Array', async () => {
  await expectLeak({ ok: true, blob: Buffer.from(FAKE_SECRET, 'utf8') });
});

test('leak sweep: secret bytes in a raw ArrayBuffer', async () => {
  const u8 = new TextEncoder().encode(FAKE_SECRET);
  await expectLeak({ ok: true, blob: u8.buffer });
});

test('leak sweep: still passes a genuinely narrowed DTO', async () => {
  const resolve = createVaultResolver({
    label: 'k',
    password: 'pw',
    client: mockClient(),
    use: () => ({ ok: true, last4: '4242', charged: 1999 }),
  });
  const out = await resolve({});
  assert.deepEqual(out, { ok: true, last4: '4242', charged: 1999 });
});
