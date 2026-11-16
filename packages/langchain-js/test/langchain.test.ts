import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RunnableLambda } from '@langchain/core/runnables';
import { tool } from '@langchain/core/tools';
import { ToolMessage } from '@langchain/core/messages';
import { z } from 'zod';
import {
  createDecoyWatch,
  decoyWatchOutputRunnable,
  decoyWatchToolInput,
  denyVaultTool,
  DenyDecoyLeakError,
  DenyLeakError,
  type DecoyHit,
  type VaultClient,
} from '../src/index.js';

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

test('output Runnable stops a scripted run and keeps the error decoy-free', async () => {
  const decoy = 'decoy-langchain-output-1234';
  const watch = createDecoyWatch({ decoys: [decoy], report: false });
  const model = RunnableLambda.from(async () => `contains ${decoy}`);
  const run = model.pipe(decoyWatchOutputRunnable(watch));
  await assert.rejects(
    () => run.invoke('prompt'),
    (error: unknown) => !String(error).includes(decoy),
  );
});

test('output Runnable returns clean text unchanged', async () => {
  const watch = createDecoyWatch({ decoys: ['decoy-langchain-output-1234'], report: false });
  const model = RunnableLambda.from(async () => 'clean final output');
  const result = await model.pipe(decoyWatchOutputRunnable(watch)).invoke('prompt');
  assert.equal(result, 'clean final output');
});

test('output Runnable catches a decoy nested in structured output', async () => {
  const decoy = 'decoy-langchain-structured-1234';
  const watch = createDecoyWatch({ decoys: [decoy], report: false });
  const model = RunnableLambda.from(async () => ({ result: { token: decoy } }));
  await assert.rejects(() => model.pipe(decoyWatchOutputRunnable(watch)).invoke('prompt'));
});

test('block:false returns output and reports the output hit through onLeak', async () => {
  const decoy = 'decoy-langchain-observe-1234';
  const hits: DecoyHit[] = [];
  const watch = createDecoyWatch({
    decoys: [decoy],
    report: false,
    block: false,
    onLeak: (hit) => {
      hits.push(hit);
    },
  });
  const model = RunnableLambda.from(async () => `observed ${decoy}`);
  const result = await model.pipe(decoyWatchOutputRunnable(watch)).invoke('prompt');
  assert.equal(result, `observed ${decoy}`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.surface, 'model_output');
});

test('output Runnable stream buffers split decoy and emits nothing before rejection', async () => {
  const decoy = 'decoy-langchain-stream-1234';
  const model = RunnableLambda.from(async function* () {
    yield 'contains decoy-langchain-';
    yield 'stream-1234';
  });
  let emitted = '';
  await assert.rejects(async () => {
    const stream = await model.pipe(decoyWatchOutputRunnable(
      createDecoyWatch({ decoys: [decoy], report: false }),
    )).stream('prompt');
    for await (const chunk of stream) emitted += chunk;
  });
  assert.equal(emitted, '');
});

test('output Runnable stream emits joined clean text after checking', async () => {
  const model = RunnableLambda.from(async function* () {
    yield 'clean ';
    yield 'stream output';
  });
  const stream = await model.pipe(decoyWatchOutputRunnable(
    createDecoyWatch({ decoys: ['decoy-langchain-stream-clean-1234'], report: false }),
  )).stream('prompt');
  const chunks: string[] = [];
  for await (const chunk of stream as unknown as AsyncIterable<string>) chunks.push(chunk);
  assert.deepEqual(chunks, ['clean stream output']);
});

test('tool-input wrapper blocks a decoy before the inner tool executes', async () => {
  const decoy = 'decoy-langchain-tool-1234';
  let executions = 0;
  const inner = tool(
    async ({ token }: { token: string }) => {
      executions += 1;
      return token;
    },
    {
      name: 'echo_token',
      description: 'Echo a token',
      schema: z.object({ token: z.string() }),
    },
  );
  const guarded = decoyWatchToolInput(
    createDecoyWatch({ decoys: [decoy], report: false }),
    inner,
  );
  await assert.rejects(
    () => guarded.invoke({ token: decoy }),
    (error: unknown) => !String(error).includes(decoy),
  );
  assert.equal(executions, 0);
});

test('tool-input wrapper executes a clean call exactly once', async () => {
  let executions = 0;
  const inner = tool(
    async ({ value }: { value: string }) => {
      executions += 1;
      return `ok:${value}`;
    },
    {
      name: 'echo_value',
      description: 'Echo a value',
      schema: z.object({ value: z.string() }),
    },
  );
  const guarded = decoyWatchToolInput(
    createDecoyWatch({ decoys: ['decoy-langchain-tool-1234'], report: false }),
    inner,
  );
  assert.equal(await guarded.invoke({ value: 'clean' }), 'ok:clean');
  assert.equal(executions, 1);
});

test('tool-input wrapper blocks a decoy in ToolCall args before execution', async () => {
  const decoy = 'decoy-langchain-toolcall-1234';
  let executions = 0;
  const inner = tool(async () => {
    executions += 1;
    return 'unreachable';
  }, {
    name: 'toolcall_input',
    description: 'ToolCall input',
    schema: z.object({ token: z.string() }),
  });
  const guarded = decoyWatchToolInput(
    createDecoyWatch({ decoys: [decoy], report: false }),
    inner,
  );
  await assert.rejects(
    () => guarded.invoke({ name: 'toolcall_input', args: { token: decoy }, id: 'call_1', type: 'tool_call' }),
    DenyDecoyLeakError,
  );
  assert.equal(executions, 0);
});

test('tool-input wrapper scans malformed raw input before schema parsing', async () => {
  const decoy = 'decoy-langchain-malformed-1234';
  let executions = 0;
  const inner = tool(async () => {
    executions += 1;
    return 'unreachable';
  }, {
    name: 'malformed_input',
    description: 'Malformed input',
    schema: z.object({ token: z.number() }),
  });
  const guarded = decoyWatchToolInput(
    createDecoyWatch({ decoys: [decoy], report: false }),
    inner,
  );
  await assert.rejects(
    () => guarded.invoke({ token: decoy }),
    (error: unknown) => {
      assert.ok(error instanceof DenyDecoyLeakError);
      assert.ok(!String(error).includes(decoy));
      assert.ok(!JSON.stringify(error).includes(decoy));
      return true;
    },
  );
  assert.equal(executions, 0);
});

test('tool-input wrapper validates and transforms schema exactly once', async () => {
  let transforms = 0;
  const inner = tool(async ({ value }: { value: string }) => value, {
    name: 'single_transform',
    description: 'Single transform',
    schema: z.object({ value: z.string().transform((value) => {
      transforms += 1;
      return value.toUpperCase();
    }) }),
  });
  const guarded = decoyWatchToolInput(
    createDecoyWatch({ decoys: ['decoy-langchain-transform-1234'], report: false }),
    inner,
  );
  assert.equal(await guarded.invoke({ value: 'clean' }), 'CLEAN');
  assert.equal(transforms, 1);
});

test('tool-input wrapper preserves inner tool fields', () => {
  const inner = tool(async () => ['content', { detail: true }], {
    name: 'preserved_fields',
    description: 'Preserved fields',
    schema: z.object({ value: z.string() }),
    responseFormat: 'content_and_artifact',
    returnDirect: true,
    tags: ['inner-tag'],
    metadata: { source: 'inner' },
  });
  const guarded = decoyWatchToolInput(
    createDecoyWatch({ decoys: ['decoy-langchain-fields-1234'], report: false }),
    inner,
  );
  const guardedFields = guarded as typeof inner;
  assert.equal(guarded.name, inner.name);
  assert.equal(guarded.description, inner.description);
  assert.equal(guarded.schema, inner.schema);
  assert.equal(guardedFields.responseFormat, inner.responseFormat);
  assert.equal(guarded.returnDirect, inner.returnDirect);
  assert.equal(guardedFields.tags, inner.tags);
  assert.equal(guardedFields.metadata, inner.metadata);
});

test('tool-input wrapper preserves ToolMessage artifact output', async () => {
  const artifact = { detail: true };
  const inner = tool(async () => ['content', artifact], {
    name: 'artifact_tool',
    description: 'Artifact tool',
    schema: z.object({ value: z.string() }),
    responseFormat: 'content_and_artifact',
  });
  const guarded = decoyWatchToolInput(
    createDecoyWatch({ decoys: ['decoy-langchain-artifact-1234'], report: false }),
    inner,
  );
  const result = await guarded.invoke({
    name: 'artifact_tool', args: { value: 'clean' }, id: 'call_artifact', type: 'tool_call',
  });
  assert.ok(result instanceof ToolMessage);
  assert.equal(result.tool_call_id, 'call_artifact');
  assert.deepEqual(result.artifact, artifact);
});

test('tool-input wrapper block:false executes and reports one hit', async () => {
  const decoy = 'decoy-langchain-tool-observe-1234';
  const hits: DecoyHit[] = [];
  let executions = 0;
  const inner = tool(async ({ value }: { value: string }) => {
    executions += 1;
    return value;
  }, {
    name: 'observed_tool_input', description: 'Observed tool input',
    schema: z.object({ value: z.string() }),
  });
  const guarded = decoyWatchToolInput(createDecoyWatch({
    decoys: [decoy], report: false, block: false, onLeak: (hit) => { hits.push(hit); },
  }), inner);
  assert.equal(await guarded.invoke({ value: decoy }), decoy);
  assert.equal(executions, 1);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.surface, 'tool_args');
});
