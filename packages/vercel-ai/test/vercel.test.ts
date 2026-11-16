import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateText,
  Output,
  simulateReadableStream,
  streamText,
  tool,
  wrapLanguageModel,
} from 'ai';
import { z } from 'zod';
import {
  createDecoyWatch,
  decoyWatchLanguageModelMiddleware,
  decoyWatchToolInput,
  denyVaultTool,
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

type V2LanguageModel = Parameters<typeof wrapLanguageModel>[0]['model'];

function scriptedModel(text: string): V2LanguageModel {
  return {
    specificationVersion: 'v2',
    provider: 'deny-test',
    modelId: 'scripted',
    supportedUrls: {},
    async doGenerate() {
      return {
        content: [{ type: 'text', text }],
        finishReason: 'stop',
        usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
        warnings: [],
      };
    },
    async doStream() {
      throw new Error('streaming is not used in these tests');
    },
  };
}

function streamingModel(textDeltas: string[]): V2LanguageModel {
  return {
    specificationVersion: 'v2',
    provider: 'deny-test',
    modelId: 'streaming',
    supportedUrls: {},
    async doGenerate() {
      throw new Error('generation is not used in these tests');
    },
    async doStream() {
      return {
        stream: simulateReadableStream({
          chunks: [
            { type: 'text-start' as const, id: 'text-1' },
            ...textDeltas.map((delta) => ({
              type: 'text-delta' as const,
              id: 'text-1',
              delta,
            })),
            { type: 'text-end' as const, id: 'text-1' },
            {
              type: 'finish' as const,
              finishReason: 'stop' as const,
              usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
            },
          ],
        }),
      };
    },
  };
}

async function consumeTextStream(model: V2LanguageModel): Promise<string> {
  const result = streamText({ model, prompt: 'prompt' });
  let text = '';
  for await (const delta of result.textStream) text += delta;
  return text;
}

test('language-model middleware stops generateText and keeps the error decoy-free', async () => {
  const decoy = 'decoy-vercel-output-1234';
  const model = wrapLanguageModel({
    model: scriptedModel(`contains ${decoy}`),
    middleware: decoyWatchLanguageModelMiddleware(
      createDecoyWatch({ decoys: [decoy], report: false }),
    ),
  });
  await assert.rejects(
    () => generateText({ model, prompt: 'prompt' }),
    (error: unknown) => !String(error).includes(decoy),
  );
});

test('language-model middleware returns clean generateText output unchanged', async () => {
  const model = wrapLanguageModel({
    model: scriptedModel('clean final output'),
    middleware: decoyWatchLanguageModelMiddleware(
      createDecoyWatch({ decoys: ['decoy-vercel-output-1234'], report: false }),
    ),
  });
  const result = await generateText({ model, prompt: 'prompt' });
  assert.equal(result.text, 'clean final output');
});

test('language-model middleware catches a decoy in structured object output', async () => {
  const decoy = 'decoy-vercel-structured-1234';
  const model = wrapLanguageModel({
    model: scriptedModel(JSON.stringify({ token: decoy })),
    middleware: decoyWatchLanguageModelMiddleware(
      createDecoyWatch({ decoys: [decoy], report: false }),
    ),
  });
  await assert.rejects(() =>
    generateText({
      model,
      prompt: 'structured prompt',
      experimental_output: Output.object({ schema: z.object({ token: z.string() }) }),
    }),
  );
});

test('block:false returns output and reports the model-output hit through onLeak', async () => {
  const decoy = 'decoy-vercel-observe-1234';
  const hits: DecoyHit[] = [];
  const watch = createDecoyWatch({
    decoys: [decoy],
    report: false,
    block: false,
    onLeak: (hit) => {
      hits.push(hit);
    },
  });
  const model = wrapLanguageModel({
    model: scriptedModel(`observed ${decoy}`),
    middleware: decoyWatchLanguageModelMiddleware(watch),
  });
  const result = await generateText({ model, prompt: 'prompt' });
  assert.equal(result.text, `observed ${decoy}`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.surface, 'model_output');
});

test('stream middleware detects a decoy split across text deltas', async () => {
  const decoy = 'decoy-vercel-stream-1234';
  const hits: DecoyHit[] = [];
  const model = wrapLanguageModel({
    model: streamingModel(['contains decoy-vercel-', 'stream-1234']),
    middleware: decoyWatchLanguageModelMiddleware(
      createDecoyWatch({
        decoys: [decoy],
        report: false,
        block: false,
        onLeak: (hit) => {
          hits.push(hit);
        },
      }),
    ),
  });
  assert.equal(await consumeTextStream(model), `contains ${decoy}`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.surface, 'model_output');
});

test('blocking stream middleware rejects with a decoy-free error', async () => {
  const decoy = 'decoy-vercel-stream-block-1234';
  const model = wrapLanguageModel({
    model: streamingModel(['contains decoy-vercel-', 'stream-block-1234']),
    middleware: decoyWatchLanguageModelMiddleware(
      createDecoyWatch({ decoys: [decoy], report: false }),
    ),
  });
  await assert.rejects(
    () => consumeTextStream(model),
    (error: unknown) => !String(error).includes(decoy),
  );
});

test('clean stream completes with identical text and no hit', async () => {
  const hits: DecoyHit[] = [];
  const model = wrapLanguageModel({
    model: streamingModel(['clean ', 'stream output']),
    middleware: decoyWatchLanguageModelMiddleware(
      createDecoyWatch({
        decoys: ['decoy-vercel-stream-clean-1234'],
        report: false,
        onLeak: (hit) => {
          hits.push(hit);
        },
      }),
    ),
  });
  assert.equal(await consumeTextStream(model), 'clean stream output');
  assert.equal(hits.length, 0);
});

test('block:false streams full decoy text and reports one hit', async () => {
  const decoy = 'decoy-vercel-stream-observe-1234';
  const hits: DecoyHit[] = [];
  const model = wrapLanguageModel({
    model: streamingModel(['full decoy-vercel-', 'stream-observe-1234']),
    middleware: decoyWatchLanguageModelMiddleware(
      createDecoyWatch({
        decoys: [decoy],
        report: false,
        block: false,
        onLeak: (hit) => {
          hits.push(hit);
        },
      }),
    ),
  });
  assert.equal(await consumeTextStream(model), `full ${decoy}`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.surface, 'model_output');
});

test('tool-input wrapper blocks a decoy before execute runs', async () => {
  const decoy = 'decoy-vercel-tool-1234';
  let executions = 0;
  const inner = tool({
    description: 'Echo a token',
    inputSchema: z.object({ token: z.string() }),
    execute: async ({ token }) => {
      executions += 1;
      return token;
    },
  });
  const guarded = decoyWatchToolInput(
    createDecoyWatch({ decoys: [decoy], report: false }),
    inner,
  );
  await assert.rejects(
    async () => guarded.execute!({ token: decoy }, { toolCallId: 'call_1', messages: [] }),
    (error: unknown) => !String(error).includes(decoy),
  );
  assert.equal(executions, 0);
});

test('tool-input wrapper executes a clean call exactly once', async () => {
  let executions = 0;
  const inner = tool({
    description: 'Echo a value',
    inputSchema: z.object({ value: z.string() }),
    execute: async ({ value }) => {
      executions += 1;
      return `ok:${value}`;
    },
  });
  const guarded = decoyWatchToolInput(
    createDecoyWatch({ decoys: ['decoy-vercel-tool-1234'], report: false }),
    inner,
  );
  const result = await guarded.execute!(
    { value: 'clean' },
    { toolCallId: 'call_1', messages: [] },
  );
  assert.equal(result, 'ok:clean');
  assert.equal(executions, 1);
});
