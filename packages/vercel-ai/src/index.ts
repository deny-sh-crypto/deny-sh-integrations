/**
 * deny-sh-vercel-ai — wrap a deny.sh vault entry as a Vercel AI SDK tool.
 *
 * The credential resolves inside the tool's `execute` boundary; only a narrowed
 * DTO is returned to the model. A fail-closed leak sweep (from
 * deny-sh-integrations-core) guarantees the raw secret never crosses back into
 * the model context.
 *
 *   import { generateText, stepCountIs } from 'ai';
 *   import { openai } from '@ai-sdk/openai';
 *   import { denyVaultTool } from 'deny-sh-vercel-ai';
 *   import { z } from 'zod';
 *
 *   const getInvoice = denyVaultTool({
 *     label: 'stripe-prod',
 *     password: process.env.VAULT_PW!,
 *     description: 'Look up a Stripe invoice by id',
 *     inputSchema: z.object({ id: z.string() }),
 *     use: async (stripeKey, { id }) => {
 *       const r = await fetch(`https://api.stripe.com/v1/invoices/${id}`, {
 *         headers: { Authorization: `Bearer ${stripeKey}` },
 *       });
 *       if (!r.ok) return { error: 'invoice_lookup_failed', status: r.status };
 *       const body = await r.json();
 *       return { id: body.id, amount_due: body.amount_due, status: body.status };
 *     },
 *   });
 *
 *   const { text } = await generateText({
 *     model: openai('gpt-4o'),
 *     tools: { getInvoice },
 *     messages,
 *     stopWhen: stepCountIs(5),
 *   });
 */

import { tool } from 'ai';
import type { LanguageModelMiddleware, Tool, ToolCallOptions } from 'ai';
import {
  type DecoyWatch,
  createVaultResolver,
  type DenyVaultClientOptions,
  type VaultClient,
} from 'deny-sh-integrations-core';

// Structural type for a schema accepted by the AI SDK's tool() (zod or
// JSON-schema). Kept loose so we don't pin a zod version.
type ToolInputSchema = unknown;

export interface DenyVaultToolConfig<TArgs = Record<string, unknown>, TResult = unknown> {
  /** Tool description shown to the model. */
  description: string;
  /** Zod (or JSON) schema for the tool args. Validated before `use`. */
  inputSchema: ToolInputSchema;
  /** Vault entry label. Provide EITHER label or id. */
  label?: string;
  /** Stable vault item id. Provide EITHER label or id. */
  id?: string;
  /** The single vault wrap password (server env, never the prompt). */
  password: string;
  /** Options forwarded to deny-sh/client (apiKey, baseUrl, ...). */
  clientOptions?: DenyVaultClientOptions;
  /**
   * Privileged work. Receives the decrypted credential + validated args.
   * Return ONLY a narrowed DTO; the raw secret must not appear in it.
   */
  use: (secret: string, args: TArgs) => Promise<TResult> | TResult;
  /** Fail-closed leak sweep of the returned DTO (default true). */
  leakSweep?: boolean;
  /** Injected vault client for testing. Defaults to deny-sh/client. */
  client?: VaultClient;
}

/**
 * Build a Vercel AI SDK tool whose `execute` resolves a deny.sh vault entry
 * inside the boundary and returns a narrowed DTO to the model.
 *
 * Returns whatever `tool()` returns, ready to drop into the `tools` map of
 * `generateText` / `streamText`.
 */
export function denyVaultTool<TArgs = Record<string, unknown>, TResult = unknown>(
  config: DenyVaultToolConfig<TArgs, TResult>,
): ReturnType<typeof tool> {
  const resolve = createVaultResolver<TArgs, TResult>({
    label: config.label,
    id: config.id,
    password: config.password,
    clientOptions: config.clientOptions,
    use: config.use,
    leakSweep: config.leakSweep,
    client: config.client,
  });

  return tool({
    description: config.description,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    inputSchema: config.inputSchema as any,
    // The AI SDK returns the execute result to the model as the tool result.
    // We return the narrowed DTO object directly (the SDK serializes it).
    execute: async (args: TArgs) => resolve(args),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);
}

/**
 * Create AI SDK language-model middleware that checks generated output.
 *
 * Attach it with `wrapLanguageModel`. `generateText` output, including JSON
 * text used for structured output, is checked before the SDK returns it.
 * Streaming output is checked when the stream ends. Text already delivered to
 * the caller before the stream ends cannot be retracted, so streaming provides
 * end-of-stream detection and reporting, not prevention. Text and tool-input
 * buffers are isolated by id. Buffer checks default to 256 KiB with a 16 KiB
 * overlap; both finite integer limits can be overridden with `maxBufferChars`
 * and `overlapChars`. A decoy longer than the overlap split across a boundary
 * is not joined. Final checks run on normal close, source error, and consumer
 * cancellation. A decoy split across separate model calls is not joined.
 */
export function decoyWatchLanguageModelMiddleware(
  watch: DecoyWatch,
  options: { maxBufferChars?: number; overlapChars?: number } = {},
): LanguageModelMiddleware {
  const maxBufferChars = options.maxBufferChars ?? 256 * 1024;
  const overlapChars = options.overlapChars ?? 16 * 1024;
  if (!Number.isInteger(maxBufferChars) || !Number.isInteger(overlapChars)
    || maxBufferChars <= 0 || overlapChars < 0 || overlapChars > maxBufferChars) {
    throw new RangeError(
      'Stream buffer limits require finite integers with 0 <= overlapChars <= maxBufferChars.',
    );
  }

  return {
    middlewareVersion: 'v2',
    wrapGenerate: async ({ doGenerate }) => {
      const result = await doGenerate();
      await watch.check(result.content, 'model_output');
      return result;
    },
    wrapStream: async ({ doStream }) => {
      const result = await doStream();
      const reader = result.stream.getReader();
      const textBuffers = new Map<string, string>();
      const reasoningBuffers = new Map<string, string>();
      const toolBuffers = new Map<string, string>();
      const toolsWithDeltas = new Set<string>();
      let cancelled = false;
      let finished = false;
      let finalizing: Promise<void> | undefined;

      const append = async (buffers: Map<string, string>, id: string, delta: string) => {
        const next = (buffers.get(id) ?? '') + delta;
        buffers.set(id, next);
        if (next.length > maxBufferChars) {
          const hits = await watch.check(next, 'model_output');
          buffers.set(id, hits.length > 0 ? '' : next.slice(-overlapChars));
        }
      };
      const checkRemaining = async () => {
        for (const value of [
          ...textBuffers.values(), ...reasoningBuffers.values(), ...toolBuffers.values(),
        ]) {
          if (value.length > 0) await watch.check(value, 'model_output');
        }
      };

      const finalize = (controller?: ReadableStreamDefaultController, terminalError?: unknown) => {
        if (finalizing) return finalizing;
        finished = true;
        finalizing = (async () => {
          let error = terminalError;
          try {
            await checkRemaining();
          } catch (checkError) {
            if (error === undefined) error = checkError;
          } finally {
            reader.releaseLock();
          }
          if (cancelled || !controller) return;
          if (error !== undefined) controller.error(error);
          else controller.close();
        })();
        return finalizing;
      };

      const stream = new ReadableStream({
        async pull(controller) {
          if (cancelled || finished) return;
          let read;
          try {
            read = await reader.read();
          } catch (error) {
            await finalize(controller, error);
            return;
          }
          if (read.done) {
            await finalize(controller);
            return;
          }
          const part = read.value;
          try {
            if (part.type === 'text-delta') {
              await append(textBuffers, part.id, part.delta);
            } else if (part.type === 'reasoning-delta') {
              await append(reasoningBuffers, part.id, part.delta);
            } else if (part.type === 'tool-input-delta') {
              toolsWithDeltas.add(part.id);
              await append(toolBuffers, part.id, part.delta);
            } else if (part.type === 'tool-call' && !toolsWithDeltas.has(part.toolCallId)) {
              await append(toolBuffers, part.toolCallId, part.input);
            } else if (![
              'stream-start', 'text-start', 'text-end', 'reasoning-start', 'reasoning-end',
              'tool-input-start', 'tool-input-end', 'tool-call', 'finish',
              'response-metadata', 'error',
            ].includes(part.type)) {
              await watch.check(part, 'model_output');
            }
          } catch (error) {
            await reader.cancel(error).catch(() => undefined);
            await finalize(controller, error);
            return;
          }
          if (!cancelled) controller.enqueue(part);
        },
        async cancel(reason) {
          cancelled = true;
          try {
            await reader.cancel(reason);
          } finally {
            await finalize();
          }
        },
      });
      return { ...result, stream };
    },
  };
}

/**
 * Wrap an AI SDK tool so validated input is checked before execution.
 *
 * The AI SDK validates tool input before calling `execute`, so this wrapper
 * cannot inspect input that fails validation. Use
 * `decoyWatchLanguageModelMiddleware` as well: its `wrapGenerate` path checks
 * raw tool-call input in `result.content` before the SDK parses it.
 *
 * Tool metadata and hooks are preserved. Tools without `execute` are returned
 * unchanged; a blocking hit rejects before the inner `execute` function runs.
 */
export function decoyWatchToolInput<TInput, TOutput>(
  watch: DecoyWatch,
  inner: Tool<TInput, TOutput>,
): Tool<TInput, TOutput> {
  const execute = inner.execute;
  if (!execute) return inner;
  return {
    ...inner,
    execute: async (input: TInput, options: ToolCallOptions) => {
      await watch.check(input, 'tool_args');
      return execute(input, options);
    },
  } as unknown as Tool<TInput, TOutput>;
}

export {
  createDecoyWatch,
  createVaultResolver,
  DenyDecoyLeakError,
  DenyToolError,
  DenyLeakError,
  isNarrowed,
} from 'deny-sh-integrations-core';
export type {
  DecoyEncoding,
  DecoyHit,
  DecoySurface,
  DecoyWatch,
  DecoyWatchConfig,
  DenyVaultClientOptions,
  VaultClient,
} from 'deny-sh-integrations-core';
