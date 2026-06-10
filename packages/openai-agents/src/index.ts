/**
 * deny-sh-openai-agents — wrap a deny.sh vault entry as an OpenAI Agents SDK tool.
 *
 * The credential resolves inside the tool's `execute` boundary; only a narrowed
 * DTO is returned to the model. A fail-closed leak sweep (from
 * deny-sh-integrations-core) guarantees the raw secret never crosses back into
 * the model context.
 *
 *   import { Agent, run } from '@openai/agents';
 *   import { denyVaultTool } from 'deny-sh-openai-agents';
 *   import { z } from 'zod';
 *
 *   const getInvoice = denyVaultTool({
 *     label: 'stripe-prod',
 *     password: process.env.VAULT_PW!,
 *     name: 'get_invoice',
 *     description: 'Look up a Stripe invoice by id',
 *     parameters: z.object({ id: z.string() }),
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
 *   const agent = new Agent({
 *     name: 'Billing',
 *     instructions: 'Help with invoices.',
 *     tools: [getInvoice],
 *   });
 *   const result = await run(agent, 'Look up invoice in_1');
 */

import { tool } from '@openai/agents';
import {
  createVaultResolver,
  type DenyVaultClientOptions,
  type VaultClient,
} from 'deny-sh-integrations-core';

// Structural type for the schema the Agents SDK `tool()` accepts (a zod v4
// schema or JSON schema). Kept loose so we don't pin a zod version on the
// consumer beyond what @openai/agents itself peers.
type ToolParameters = unknown;

export interface DenyVaultToolConfig<TArgs = Record<string, unknown>, TResult = unknown> {
  /** Tool name the model calls (e.g. 'get_invoice'). */
  name: string;
  /** Tool description shown to the model. */
  description: string;
  /** Zod (or JSON) schema for the tool args. Validated by the SDK before `use`. */
  parameters: ToolParameters;
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
 * Build an OpenAI Agents SDK tool whose `execute` resolves a deny.sh vault
 * entry inside the boundary and returns a narrowed DTO to the model.
 *
 * Returns whatever `tool()` returns (a FunctionTool), ready to drop into the
 * `tools` array of `new Agent({ ... })`.
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
    name: config.name,
    description: config.description,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    parameters: config.parameters as any,
    // The SDK passes the validated args object to execute and returns the
    // result to the model as the tool result. We return the narrowed DTO
    // directly (the SDK serializes it).
    execute: async (args: TArgs) => resolve(args),
    // The Agents SDK's DEFAULT tool-error handler swallows any thrown error
    // into a generic self-heal string handed back to the model. deny.sh fails
    // CLOSED instead: the resolver wraps every vault/use() failure into a
    // secret-scrubbed DenyToolError, and a leak into DenyLeakError, so the ONLY
    // things that can escape execute() are already-scrubbed deny.sh errors.
    // Setting errorFunction:null lets those propagate (loud, fail-closed),
    // matching the LangChain/Vercel adapters where the throw escapes the tool
    // boundary rather than being silently absorbed back into the model context.
    errorFunction: null,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);
}

export { createVaultResolver, DenyToolError, DenyLeakError, isNarrowed } from 'deny-sh-integrations-core';
export type { DenyVaultClientOptions, VaultClient } from 'deny-sh-integrations-core';
