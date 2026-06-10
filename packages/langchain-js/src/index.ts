/**
 * @deny-sh/langchain — wrap a deny.sh vault entry as a LangChain v1 tool.
 *
 * The credential is resolved + consumed inside the tool boundary; only a
 * narrowed DTO is returned to the agent. A fail-closed leak sweep (from
 * @deny-sh/integrations-core) guarantees the raw secret never crosses back
 * into the model context.
 *
 *   import { denyVaultTool } from '@deny-sh/langchain';
 *   import { z } from 'zod';
 *
 *   const invoiceTool = denyVaultTool({
 *     label: 'stripe-prod',
 *     password: process.env.VAULT_PW!,
 *     name: 'get_invoice',
 *     description: 'Look up a Stripe invoice by id',
 *     schema: z.object({ id: z.string() }),
 *     use: async (stripeKey, { id }) => {
 *       const r = await fetch(`https://api.stripe.com/v1/invoices/${id}`, {
 *         headers: { Authorization: `Bearer ${stripeKey}` },
 *       });
 *       const body = await r.json();
 *       return { id: body.id, amount_due: body.amount_due, status: body.status };
 *     },
 *   });
 *
 *   const agent = createAgent({ model, tools: [invoiceTool] });
 */

import { tool } from '@langchain/core/tools';
import type { StructuredToolInterface } from '@langchain/core/tools';
import {
  createVaultResolver,
  type DenyVaultClientOptions,
  type VaultClient,
} from '@deny-sh/integrations-core';

// Minimal structural type for a zod schema, so we don't force a zod version on
// the consumer beyond what LangChain itself peers. LangChain's `tool()` accepts
// a zod schema (or JSON schema) here.
type ToolSchema = unknown;

export interface DenyVaultToolConfig<TArgs = Record<string, unknown>, TResult = unknown> {
  /** LangChain tool name the model calls (e.g. 'get_invoice'). */
  name: string;
  /** LangChain tool description shown to the model. */
  description: string;
  /** Zod (or JSON) schema for the tool args. Validated by LangChain before `use`. */
  schema: ToolSchema;
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
 * Build a LangChain `tool` whose execution resolves a deny.sh vault entry
 * inside the boundary and returns a narrowed DTO to the agent.
 *
 * Returns whatever `tool()` returns (a StructuredTool / RunnableToolLike),
 * ready to drop into `createAgent({ tools: [...] })`.
 */
export function denyVaultTool<TArgs = Record<string, unknown>, TResult = unknown>(
  config: DenyVaultToolConfig<TArgs, TResult>,
): StructuredToolInterface {
  const resolve = createVaultResolver<TArgs, TResult>({
    label: config.label,
    id: config.id,
    password: config.password,
    clientOptions: config.clientOptions,
    use: config.use,
    leakSweep: config.leakSweep,
    client: config.client,
  });

  const built = tool(
    async (args: unknown) => {
      const dto = await resolve(args as TArgs);
      // LangChain tools conventionally return a string; stringify objects so
      // the model receives clean JSON, not "[object Object]".
      return typeof dto === 'string' ? dto : JSON.stringify(dto);
    },
    {
      name: config.name,
      description: config.description,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      schema: config.schema as any,
    },
  );
  return built as unknown as StructuredToolInterface;
}

export { createVaultResolver, DenyToolError, DenyLeakError, isNarrowed } from '@deny-sh/integrations-core';
export type { DenyVaultClientOptions, VaultClient } from '@deny-sh/integrations-core';
