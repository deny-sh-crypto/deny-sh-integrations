import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createDecoyWatch,
  createVaultResolver,
  isNarrowed,
  DenyDecoyLeakError,
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

const DECOY = 'decoy-value-1234';

test('decoy watch detects each supported encoding', () => {
  const cases: Array<{ decoy: string; encoded: string; encoding: string }> = [
    { decoy: DECOY, encoded: `prefix ${DECOY} suffix`, encoding: 'plain' },
    {
      decoy: DECOY,
      encoded: Buffer.from(DECOY, 'utf8').toString('base64'),
      encoding: 'base64',
    },
    {
      decoy: DECOY,
      encoded: Buffer.from(DECOY, 'utf8').toString('base64').replace(/=+$/, ''),
      encoding: 'base64',
    },
    {
      decoy: 'decoyÿÿvalue',
      encoded: Buffer.from('decoyÿÿvalue', 'utf8').toString('base64url'),
      encoding: 'base64url',
    },
    {
      decoy: 'decoyÿÿvalue',
      encoded: Buffer.from('decoyÿÿvalue', 'utf8')
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_'),
      encoding: 'base64url',
    },
    {
      decoy: DECOY,
      encoded: Buffer.from(DECOY, 'utf8').toString('hex').toUpperCase(),
      encoding: 'hex',
    },
    {
      decoy: 'decoy value?',
      encoded: encodeURIComponent('decoy value?'),
      encoding: 'percent',
    },
    {
      decoy: DECOY,
      encoded: [...DECOY].join(' \n'),
      encoding: 'spaced',
    },
  ];
  for (const item of cases) {
    const watch = createDecoyWatch({ decoys: [item.decoy], report: false });
    assert.equal(watch.scan(item.encoded, 'model_output')[0]?.encoding, item.encoding);
  }
});

test('decoy watch ignores unrelated text', () => {
  const watch = createDecoyWatch({ decoys: [DECOY], report: false });
  assert.deepEqual(watch.scan('ordinary agent output', 'model_output'), []);
});

test('decoy watch traverses objects, arrays, Map, and Set', () => {
  const decoys = ['object-decoy-1', 'array-decoy-22', 'map-decoy-333', 'set-decoy-444'];
  const watch = createDecoyWatch({ decoys, report: false });
  const value = {
    nested: { value: decoys[0] },
    array: ['safe', decoys[1]],
    map: new Map([['key', decoys[2]]]),
    set: new Set(['safe', decoys[3]]),
  };
  assert.equal(watch.scan(value, 'other').length, 4);
});

test('decoy watch rejects short decoys with deny_config_error', () => {
  assert.throws(
    () => createDecoyWatch({ decoys: ['short'] }),
    (error: unknown) => error instanceof DenyToolError && error.code === 'deny_config_error',
  );
});

test('decoy report carries only fingerprint, surface, and source', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const fakeFetch: typeof fetch = async (input, init) => {
    calls.push({ url: String(input), init });
    return new Response(JSON.stringify({ ok: true, matched: true }), { status: 200 });
  };
  const watch = createDecoyWatch({
    decoys: [{ label: 'demo', value: DECOY }],
    clientOptions: { apiKey: 'test-key', baseUrl: 'https://example.invalid/api/' },
    fetch: fakeFetch,
    block: false,
  });
  const hits = await watch.check(`out: ${DECOY}`, 'model_output');
  assert.equal(hits.length, 1);
  assert.equal(calls[0]?.url, 'https://example.invalid/v1/decoy-tripwires/observe');
  const bodyText = String(calls[0]?.init?.body);
  const body = JSON.parse(bodyText) as Record<string, unknown>;
  assert.deepEqual(body, {
    tripwire_hash: watch.fingerprints()[0],
    surface: 'model_output',
    source: 'deny-sh-integrations-core/0.2.0',
  });
  assert.ok(!bodyText.includes(DECOY));
  assert.equal((calls[0]?.init?.headers as Record<string, string>).Authorization, 'Bearer test-key');
});

test('tripwire routing strips only a terminal /api path segment', async () => {
  const previousApiUrl = process.env.DENY_API_URL;
  delete process.env.DENY_API_URL;
  try {
    const cases: Array<{ baseUrl?: string; expected: string }> = [
      { expected: 'https://deny.sh/v1/decoy-tripwires/observe' },
      {
        baseUrl: 'https://example.invalid/api/',
        expected: 'https://example.invalid/v1/decoy-tripwires/observe',
      },
      {
        baseUrl: 'http://127.0.0.1:3000',
        expected: 'http://127.0.0.1:3000/v1/decoy-tripwires/observe',
      },
      {
        baseUrl: 'https://example.invalid/apiary',
        expected: 'https://example.invalid/apiary/v1/decoy-tripwires/observe',
      },
    ];
    for (const item of cases) {
      const urls: string[] = [];
      const watch = createDecoyWatch({
        decoys: [DECOY],
        clientOptions: {
          apiKey: 'test-key',
          ...(item.baseUrl === undefined ? {} : { baseUrl: item.baseUrl }),
        },
        fetch: async (input) => {
          urls.push(String(input));
          return new Response('{}', { status: 200 });
        },
        block: false,
      });
      await watch.check(DECOY, 'model_output');
      assert.equal(urls[0], item.expected);
    }
  } finally {
    if (previousApiUrl === undefined) delete process.env.DENY_API_URL;
    else process.env.DENY_API_URL = previousApiUrl;
  }
});

test('decoy report network failure is swallowed and observed safely', async () => {
  const failures: Array<{ fingerprint: string; surface: string; error?: string }> = [];
  const watch = createDecoyWatch({
    decoys: [DECOY],
    clientOptions: { apiKey: 'test-key' },
    fetch: async () => {
      throw new Error(`offline for ${DECOY}`);
    },
    onReportError: (info) => failures.push(info),
    block: false,
  });
  const hits = await watch.check(DECOY, 'model_output');
  assert.equal(hits.length, 1);
  assert.deepEqual(failures, [
    {
      fingerprint: hits[0]?.fingerprint,
      surface: 'model_output',
      error: 'offline for [deny:redacted]',
    },
  ]);
  assert.ok(!JSON.stringify(failures).includes(DECOY));
});

test('decoy report is bounded when injected fetch ignores abort', async () => {
  const failures: Array<{ error?: string }> = [];
  const watch = createDecoyWatch({
    decoys: [DECOY],
    clientOptions: { apiKey: 'test-key' },
    fetch: async () => new Promise<Response>(() => {}),
    onReportError: (info) => failures.push(info),
    reportTimeoutMs: 10,
    block: false,
  });
  const completed = await Promise.race([
    watch.check(DECOY).then(() => true),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 250)),
  ]);
  assert.equal(completed, true);
  assert.equal(failures[0]?.error, 'timeout');
});

test('decoy report non-2xx status is swallowed and observed', async () => {
  const failures: Array<{ fingerprint: string; surface: string; status?: number }> = [];
  const watch = createDecoyWatch({
    decoys: [DECOY],
    clientOptions: { apiKey: 'test-key' },
    fetch: async () => new Response('{}', { status: 503 }),
    onReportError: (info) => failures.push(info),
    block: false,
  });
  const hits = await watch.check(DECOY, 'tool_args');
  assert.deepEqual(failures, [
    { fingerprint: hits[0]?.fingerprint, surface: 'tool_args', status: 503 },
  ]);
});

test('onReportError exceptions never propagate', async () => {
  const watch = createDecoyWatch({
    decoys: [DECOY],
    clientOptions: { apiKey: 'test-key' },
    fetch: async () => new Response('{}', { status: 500 }),
    onReportError: () => {
      throw new Error('observer failed');
    },
    block: false,
  });
  const hits = await watch.check(DECOY, 'model_output');
  assert.equal(hits.length, 1);
});

test('block true throws scrubbed DenyDecoyLeakError after callback', async () => {
  let callbackCount = 0;
  const watch = createDecoyWatch({
    decoys: [DECOY],
    report: false,
    onLeak: () => {
      callbackCount += 1;
    },
  });
  await assert.rejects(() => watch.check(DECOY, 'tool_result'), (error: unknown) => {
    assert.ok(error instanceof DenyDecoyLeakError);
    assert.ok(!error.message.includes(DECOY));
    return true;
  });
  assert.equal(callbackCount, 1);
});

test('block false returns hits and onLeak runs once per hit', async () => {
  const seen: string[] = [];
  const watch = createDecoyWatch({
    decoys: [DECOY, 'second-decoy-5678'],
    report: false,
    block: false,
    onLeak: (hit) => {
      seen.push(hit.fingerprint);
    },
  });
  const hits = await watch.check(`${DECOY} second-decoy-5678`, 'tool_args');
  assert.equal(hits.length, 2);
  assert.deepEqual(seen.sort(), hits.map((hit) => hit.fingerprint).sort());
});

test('arm posts each fingerprint as plaintext tripwire', async () => {
  const bodies: Array<Record<string, unknown>> = [];
  const urls: string[] = [];
  const fakeFetch: typeof fetch = async (input, init) => {
    urls.push(String(input));
    bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  };
  const watch = createDecoyWatch({
    decoys: [{ label: 'first', value: DECOY }, 'second-decoy-5678'],
    clientOptions: { apiKey: 'test-key', baseUrl: 'https://example.invalid/api' },
    fetch: fakeFetch,
    report: false,
  });
  assert.deepEqual(await watch.arm(), { armed: 2 });
  assert.deepEqual(urls, [
    'https://example.invalid/v1/decoy-tripwires',
    'https://example.invalid/v1/decoy-tripwires',
  ]);
  assert.deepEqual(
    bodies.map((body) => body.tripwire_kind),
    ['plaintext', 'plaintext'],
  );
  assert.deepEqual(
    bodies.map((body) => body.tripwire_hash),
    watch.fingerprints(),
  );
  assert.equal(bodies[0]?.label, 'first');
});

test('report false and unresolved API key make check network-free', async () => {
  let calls = 0;
  const fakeFetch: typeof fetch = async () => {
    calls += 1;
    return new Response('{}', { status: 200 });
  };
  const explicitOff = createDecoyWatch({
    decoys: [DECOY],
    clientOptions: { apiKey: 'test-key' },
    fetch: fakeFetch,
    report: false,
    block: false,
  });
  const noKey = createDecoyWatch({
    decoys: [DECOY],
    clientOptions: { apiKey: '' },
    fetch: fakeFetch,
    block: false,
  });
  await explicitOff.check(DECOY);
  await noKey.check(DECOY);
  assert.equal(calls, 0);
});
