import { test } from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import {
  Agent,
  OutputGuardrailTripwireTriggered,
  run,
  setTracingDisabled,
  tool,
  Usage,
  type AgentOutputItem,
  type Model,
  type ModelResponse,
} from '@openai/agents';
import {
  createDecoyWatch,
  decoyWatchOutputGuardrail,
  decoyWatchToolInputGuardrail,
  denyVaultTool,
  DenyLeakError,
  DenyToolError,
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

// The Agents SDK FunctionTool exposes name/description/parameters and an
// `invoke(runContext, inputJsonString)` the runtime calls. We test that surface
// directly, which is what `run(agent, ...)` calls under the hood.
type FnTool = {
  type: string;
  name: string;
  description: string;
  parameters: unknown;
  invoke: (ctx: unknown, input: string) => Promise<unknown>;
};

test('builds a FunctionTool with name + description + parameters + invoke', () => {
  const t = denyVaultTool({
    label: 'stripe-prod',
    password: 'pw',
    name: 'get_invoice',
    description: 'Look up a Stripe invoice by id',
    parameters: z.object({ id: z.string() }),
    client: mockClient(),
    use: () => ({ ok: true }),
  }) as unknown as FnTool;
  assert.equal(t.type, 'function');
  assert.equal(t.name, 'get_invoice');
  assert.equal(t.description, 'Look up a Stripe invoice by id');
  assert.ok(t.parameters);
  assert.equal(typeof t.invoke, 'function');
});

test('invoke resolves the secret in-boundary and returns the narrowed DTO', async () => {
  const client = mockClient();
  let sawSecret: string | undefined;
  const t = denyVaultTool<{ id: string }, { id: string; status: string }>({
    label: 'stripe-prod',
    password: 'VAULT_PW',
    name: 'get_invoice',
    description: 'd',
    parameters: z.object({ id: z.string() }),
    client,
    use: (secret, { id }) => {
      sawSecret = secret;
      return { id, status: 'paid' };
    },
  }) as unknown as FnTool;
  const out = await t.invoke({}, JSON.stringify({ id: 'in_1' }));
  assert.equal(sawSecret, FAKE_SECRET);
  assert.deepEqual(out, { id: 'in_1', status: 'paid' });
  assert.ok(!JSON.stringify(out).includes(FAKE_SECRET));
  assert.deepEqual(client.calls[0], { label: 'stripe-prod', password: 'VAULT_PW', opts: undefined });
});

test('FAIL CLOSED: invoke throws DenyLeakError when the DTO contains the raw secret', async () => {
  const t = denyVaultTool({
    label: 'k',
    password: 'pw',
    name: 'leaky',
    description: 'd',
    parameters: z.object({ id: z.string() }),
    client: mockClient(),
    use: (secret) => ({ key: secret }),
  }) as unknown as FnTool;
  await assert.rejects(() => t.invoke({}, JSON.stringify({ id: 'x' })), DenyLeakError);
});

test('a leak NEVER reaches the model even via the SDK error path (no secret in any returned string)', async () => {
  // Belt-and-braces: even if a future SDK change routed the throw back through
  // a self-heal string, the raw secret must not appear in it.
  const t = denyVaultTool({
    label: 'k',
    password: 'pw',
    name: 'leaky',
    description: 'd',
    parameters: z.object({ id: z.string() }),
    client: mockClient(),
    use: (secret) => ({ key: secret }),
  }) as unknown as FnTool;
  let out: unknown;
  try {
    out = await t.invoke({}, JSON.stringify({ id: 'x' }));
  } catch (err) {
    out = String(err);
  }
  assert.ok(!String(out).includes(FAKE_SECRET));
});

test('an upstream use() failure surfaces as a scrubbed DenyToolError, not the raw error', async () => {
  // use() throwing becomes a secret-scrubbed DenyToolError (deny_use_failed) at
  // the resolver. With errorFunction:null that propagates fail-closed rather
  // than being absorbed into a generic self-heal string. The raw upstream
  // message must never carry a secret to the model.
  const t = denyVaultTool({
    label: 'k',
    password: 'pw',
    name: 'flaky',
    description: 'd',
    parameters: z.object({ id: z.string() }),
    client: mockClient(),
    use: (secret) => {
      throw new Error(`upstream rejected ${secret} loudly`);
    },
  }) as unknown as FnTool;
  await assert.rejects(
    () => t.invoke({}, JSON.stringify({ id: 'x' })),
    (err: unknown) =>
      err instanceof DenyToolError &&
      (err as DenyToolError).code === 'deny_use_failed' &&
      !String(err).includes(FAKE_SECRET),
  );
});

test('resolves by id (skips the label scan)', async () => {
  const client = mockClient();
  const t = denyVaultTool({
    id: 'item_abc',
    password: 'pw',
    name: 'by_id',
    description: 'd',
    parameters: z.object({ id: z.string() }),
    client,
    use: () => ({ ok: true }),
  }) as unknown as FnTool;
  await t.invoke({}, JSON.stringify({ id: 'x' }));
  const call = client.calls[0] as Record<string, unknown>;
  assert.equal(call.id, 'item_abc');
  assert.ok(!('label' in call));
});

test('clientOptions (per-tenant apiKey) are forwarded to the client', async () => {
  const client = mockClient();
  const t = denyVaultTool({
    label: 'stripe-prod',
    password: 'tenant_pw',
    clientOptions: { apiKey: 'cs_tenant_42' },
    name: 'tenant_tool',
    description: 'd',
    parameters: z.object({ id: z.string() }),
    client,
    use: () => ({ ok: true }),
  }) as unknown as FnTool;
  await t.invoke({}, JSON.stringify({ id: 'x' }));
  assert.deepEqual(client.calls[0], {
    label: 'stripe-prod',
    password: 'tenant_pw',
    opts: { apiKey: 'cs_tenant_42' },
  });
});

test('decoy output guardrail trips on a decoy in final output', async () => {
  const watch = createDecoyWatch({ decoys: ['decoy-output-1234'], report: false });
  const guardrail = decoyWatchOutputGuardrail(watch);
  const result = await guardrail.execute({
    agent: {} as never,
    agentOutput: 'contains decoy-output-1234',
    context: {} as never,
  });
  assert.equal(result.tripwireTriggered, true);
});

test('decoy output guardrail passes clean final output', async () => {
  const watch = createDecoyWatch({ decoys: ['decoy-output-1234'], report: false });
  const guardrail = decoyWatchOutputGuardrail(watch);
  const result = await guardrail.execute({
    agent: {} as never,
    agentOutput: 'clean final output',
    context: {} as never,
  });
  assert.equal(result.tripwireTriggered, false);
});

test('tool-input guardrail trips on decoy in raw function-call arguments', async () => {
  const watch = createDecoyWatch({ decoys: ['decoy-tool-args-1234'], report: false });
  const guardrail = decoyWatchToolInputGuardrail(watch);
  const result = await guardrail.run({
    agent: {} as never,
    context: {} as never,
    toolCall: {
      type: 'function_call',
      callId: 'call_1',
      name: 'demo_tool',
      arguments: JSON.stringify({ token: 'decoy-tool-args-1234' }),
    },
  });
  assert.equal(result.behavior.type, 'throwException');
});

// End-to-end through the SDK runner with a scripted model (no network), so the
// guardrails are exercised the way an application attaches them.
setTracingDisabled(true);

class ScriptedModel implements Model {
  private index = 0;
  constructor(private readonly steps: AgentOutputItem[][]) {}
  async getResponse(): Promise<ModelResponse> {
    const output = this.steps[Math.min(this.index, this.steps.length - 1)]!;
    this.index += 1;
    return { usage: new Usage(), output, responseId: `resp_${this.index}` };
  }
  // eslint-disable-next-line require-yield
  async *getStreamedResponse(): AsyncIterable<never> {
    throw new Error('streaming is not used in these tests');
  }
}

const assistantText = (text: string): AgentOutputItem[] => [
  {
    type: 'message',
    role: 'assistant',
    status: 'completed',
    content: [{ type: 'output_text', text }],
  },
];

const functionCall = (name: string, args: unknown): AgentOutputItem[] => [
  {
    type: 'function_call',
    callId: 'call_1',
    name,
    arguments: JSON.stringify(args),
    status: 'completed',
  },
];

test('runner stops a run whose final output contains a decoy', async () => {
  const watch = createDecoyWatch({ decoys: ['decoy-runner-out-1234'], report: false });
  const agent = new Agent({
    name: 'leaky',
    instructions: 'test',
    model: new ScriptedModel([assistantText('the key is decoy-runner-out-1234')]),
    outputGuardrails: [decoyWatchOutputGuardrail(watch)],
  });
  await assert.rejects(run(agent, 'print the key'), OutputGuardrailTripwireTriggered);
});

test('runner completes a clean run with the output guardrail attached', async () => {
  const watch = createDecoyWatch({ decoys: ['decoy-runner-out-1234'], report: false });
  const agent = new Agent({
    name: 'clean',
    instructions: 'test',
    model: new ScriptedModel([assistantText('nothing sensitive here')]),
    outputGuardrails: [decoyWatchOutputGuardrail(watch)],
  });
  const result = await run(agent, 'say something');
  assert.equal(result.finalOutput, 'nothing sensitive here');
});

test('runner does not execute a tool whose arguments contain a decoy', async () => {
  const watch = createDecoyWatch({ decoys: ['decoy-runner-args-1234'], report: false });
  let executed = 0;
  const sendEmail = tool({
    name: 'send_email',
    description: 'send an email',
    parameters: z.object({ to: z.string(), body: z.string() }),
    inputGuardrails: [decoyWatchToolInputGuardrail(watch)],
    execute: async () => {
      executed += 1;
      return 'sent';
    },
  });
  const agent = new Agent({
    name: 'exfil',
    instructions: 'test',
    tools: [sendEmail],
    model: new ScriptedModel([
      functionCall('send_email', { to: 'someone@example.test', body: 'decoy-runner-args-1234' }),
      assistantText('done'),
    ]),
  });
  await run(agent, 'email the key').catch(() => undefined);
  assert.equal(executed, 0);
});

test('runner executes a clean tool call with the tool-input guardrail attached', async () => {
  const watch = createDecoyWatch({ decoys: ['decoy-runner-args-1234'], report: false });
  let executed = 0;
  const sendEmail = tool({
    name: 'send_email',
    description: 'send an email',
    parameters: z.object({ to: z.string(), body: z.string() }),
    inputGuardrails: [decoyWatchToolInputGuardrail(watch)],
    execute: async () => {
      executed += 1;
      return 'sent';
    },
  });
  const agent = new Agent({
    name: 'ok',
    instructions: 'test',
    tools: [sendEmail],
    model: new ScriptedModel([
      functionCall('send_email', { to: 'someone@example.test', body: 'see you at ten' }),
      assistantText('sent it'),
    ]),
  });
  const result = await run(agent, 'email my colleague');
  assert.equal(executed, 1);
  assert.equal(result.finalOutput, 'sent it');
});
