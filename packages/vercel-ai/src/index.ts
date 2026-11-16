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
 * text used for structured output, is checked before the SDK returns it. This
 * middleware does not wrap `doStream`: `streamText` chunks may already reach
 * the caller and cannot be retracted, so streaming output is not covered.
 */
export function decoyWatchLanguageModelMiddleware(
  watch: DecoyWatch,
): LanguageModelMiddleware {
  return {
    middlewareVersion: 'v2',
    wrapGenerate: async ({ doGenerate }) => {
      const result = await doGenerate();
      await watch.check(result.content, 'model_output');
      return result;
    },
  };
}

/**
 * Wrap an AI SDK tool so validated input is checked before execution.
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
