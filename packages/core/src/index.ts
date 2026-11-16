/**
 * deny-sh-integrations-core — framework-agnostic vault-entry-as-tool builder.
 *
 * Every deny.sh framework adapter (LangChain, Vercel AI SDK, ...) wraps this
 * single resolver. It enforces the deniable/agent-safety contract that the
 * marketing pages promise:
 *
 *   1. The raw credential is resolved from the deny.sh managed vault and
 *      decrypted *inside this resolver's closure*, server-side.
 *   2. Your `use(secret, args)` callback is the ONLY place the plaintext
 *      credential exists. You make the privileged call there and return a
 *      narrowed DTO.
 *   3. The narrowed DTO is leak-swept before it is ever handed back to the
 *      framework (and therefore to the model). If the raw secret is found
 *      anywhere in the returned value, the resolver FAILS CLOSED: it throws
 *      and the secret never crosses the trust boundary.
 *
 * The framework adapters add nothing to the security model; they only adapt
 * the shape of `createVaultResolver` into each framework's tool interface.
 */

import { vaultGet as defaultVaultGet, vaultGetById as defaultVaultGetById } from 'deny-sh/client';
import { createHash } from 'node:crypto';

/** Options forwarded to the deny-sh vault client. */
export interface DenyVaultClientOptions {
  /** Bearer API key. Defaults to process.env.DENY_API_KEY inside deny-sh/client. */
  apiKey?: string;
  /** API base URL. Defaults to process.env.DENY_API_URL || 'https://deny.sh/api'. */
  baseUrl?: string;
  /** Max vault items to scan when resolving a label. */
  labelIndexLimit?: number;
  /** AbortSignal forwarded to the underlying fetch. */
  signal?: AbortSignal;
}

/**
 * Pluggable vault client. Defaults to the real `deny-sh/client`. Injectable so
 * adapters and unit tests can mock the network round-trip without touching the
 * security logic.
 */
export interface VaultClient {
  vaultGet(label: string, password: string, opts?: Record<string, unknown>): Promise<string>;
  vaultGetById(id: string, password: string, opts?: Record<string, unknown>): Promise<string>;
}

export interface DenyVaultResolverConfig<TArgs = unknown, TResult = unknown> {
  /**
   * The vault entry label (e.g. 'stripe-prod'). Provide EITHER `label` or `id`.
   * `id` skips the label-index scan and is recommended for high-volume agents.
   */
  label?: string;
  /** A stable vault item id. Provide EITHER `label` or `id`. */
  id?: string;
  /**
   * The single vault wrap password (derives the AES-256 key locally).
   * Lives in your server environment, never in the agent prompt.
   */
  password: string;
  /** Options forwarded to the deny-sh vault client (apiKey, baseUrl, ...). */
  clientOptions?: DenyVaultClientOptions;
  /**
   * The privileged work. Receives the decrypted credential and the validated
   * tool args. Make the upstream call here and return ONLY a narrowed DTO.
   * The raw `secret` MUST NOT appear anywhere in the returned value.
   */
  use: (secret: string, args: TArgs) => Promise<TResult> | TResult;
  /**
   * Fail-closed leak sweep of the returned DTO (default true). When on, the
   * resolver scans the value `use()` returns for the raw secret and throws
   * (returning nothing) if it is present. Turn off ONLY if you have an
   * independent guarantee and accept the risk.
   */
  leakSweep?: boolean;
  /** Injected vault client (testing / custom transport). Defaults to deny-sh/client. */
  client?: VaultClient;
}

/** Thrown when the vault fetch/decrypt fails or `use()` throws. Secret-scrubbed. */
export class DenyToolError extends Error {
  readonly code: string;
  readonly cause?: unknown;
  constructor(code: string, message: string, cause?: unknown) {
    super(message);
    this.name = 'DenyToolError';
    this.code = code;
    this.cause = cause;
  }
}

/** Thrown by the fail-closed leak sweep when the raw secret is found in the DTO. */
export class DenyLeakError extends Error {
  readonly code = 'deny_secret_leak';
  constructor(message: string) {
    super(message);
    this.name = 'DenyLeakError';
  }
}

const DEFAULT_CLIENT: VaultClient = {
  vaultGet: defaultVaultGet,
  vaultGetById: defaultVaultGetById,
};

/**
 * Recursively scan a value the `use()` callback returned for the raw secret.
 * Strings are checked directly; objects/arrays are walked; other primitives
 * are coerced to string and checked (defends against a secret stuffed into a
 * number-like or custom toString). Map/Set are walked too.
 */
function valueContains(
  value: unknown,
  matches: (text: string) => boolean,
  seen: WeakSet<object>,
): boolean {
  if (value == null) return false;
  const t = typeof value;
  if (t === 'string') return matches(value as string);
  if (t === 'number' || t === 'boolean' || t === 'bigint') {
    return matches(String(value));
  }
  if (t === 'symbol') {
    return matches((value as symbol).toString());
  }
  if (t === 'function') {
    // Defend against a secret captured in the source text of a returned fn.
    try {
      return matches(Function.prototype.toString.call(value));
    } catch {
      return false;
    }
  }
  if (t === 'object') {
    const obj = value as object;
    if (seen.has(obj)) return false;
    seen.add(obj);
    if (Array.isArray(obj)) {
      for (const el of obj) if (valueContains(el, matches, seen)) return true;
      return false;
    }
    if (obj instanceof Map) {
      for (const [k, v] of obj) {
        if (valueContains(k, matches, seen) || valueContains(v, matches, seen)) return true;
      }
      return false;
    }
    if (obj instanceof Set) {
      for (const el of obj) if (valueContains(el, matches, seen)) return true;
      return false;
    }
    // Binary carriers: a secret can cross the boundary as raw bytes in a
    // TypedArray / Buffer / DataView / ArrayBuffer without ever being a string.
    // Decode the bytes latin1 + utf8 and scan for the secret's byte sequence.
    if (ArrayBuffer.isView(obj) || obj instanceof ArrayBuffer) {
      try {
        const bytes =
          obj instanceof ArrayBuffer
            ? new Uint8Array(obj)
            : new Uint8Array(
                (obj as ArrayBufferView).buffer,
                (obj as ArrayBufferView).byteOffset,
                (obj as ArrayBufferView).byteLength,
              );
        // latin1 gives a 1:1 byte->char view so a byte-spliced ASCII secret is
        // visible; utf8 catches a normally-encoded string buffer.
        let latin1 = '';
        for (let i = 0; i < bytes.length; i++) latin1 += String.fromCharCode(bytes[i]);
        if (matches(latin1)) return true;
        try {
          if (matches(new TextDecoder('utf-8').decode(bytes))) return true;
        } catch {
          /* ignore decode failure */
        }
      } catch {
        /* ignore */
      }
      return false;
    }
    // Check ALL own keys (string AND symbol, enumerable AND non-enumerable)
    // plus getters, so a secret hidden behind a Symbol key, a non-enumerable
    // property, or a lazily-revealing getter cannot evade the sweep.
    for (const key of Reflect.ownKeys(obj)) {
      if (typeof key === 'string' && matches(key)) return true;
      let v: unknown;
      try {
        v = (obj as Record<string | symbol, unknown>)[key];
      } catch {
        // A throwing getter cannot hand the secret to the model, skip it.
        continue;
      }
      if (valueContains(v, matches, seen)) return true;
    }
    // Walk prototype-chain getters too (own-key walk above misses inherited
    // accessor properties that a serializer/framework could still read).
    let proto = Object.getPrototypeOf(obj);
    while (proto && proto !== Object.prototype && proto !== Array.prototype) {
      for (const key of Object.getOwnPropertyNames(proto)) {
        const desc = Object.getOwnPropertyDescriptor(proto, key);
        if (desc && typeof desc.get === 'function') {
          let v: unknown;
          try {
            v = (obj as Record<string, unknown>)[key];
          } catch {
            continue;
          }
          if (valueContains(v, matches, seen)) return true;
        }
      }
      proto = Object.getPrototypeOf(proto);
    }
    // Also sweep a custom toString, in case the DTO renders the secret lazily.
    try {
      const s = String(obj);
      if (s !== '[object Object]' && matches(s)) return true;
    } catch {
      /* ignore */
    }
    return false;
  }
  return false;
}

function containsSecret(value: unknown, secret: string, seen: WeakSet<object>): boolean {
  if (secret.length === 0) return false;
  return valueContains(value, (text) => text.includes(secret), seen);
}

export type DecoySurface = 'model_output' | 'tool_args' | 'tool_result' | 'other';
export type DecoyEncoding = 'plain' | 'base64' | 'base64url' | 'hex' | 'percent' | 'spaced';

export interface DecoyHit {
  label?: string;
  fingerprint: string;
  surface: DecoySurface;
  encoding: DecoyEncoding;
}

export interface DecoyWatchConfig {
  decoys: Array<string | { label?: string; value: string }>;
  clientOptions?: DenyVaultClientOptions;
  report?: boolean;
  block?: boolean;
  onLeak?: (hit: DecoyHit) => void | Promise<void>;
  onReportError?: (info: {
    fingerprint: string;
    surface: DecoySurface;
    status?: number;
    error?: string;
  }) => void;
  fetch?: typeof fetch;
  reportTimeoutMs?: number;
}

export interface DecoyWatch {
  scan(value: unknown, surface?: DecoySurface): DecoyHit[];
  check(value: unknown, surface?: DecoySurface): Promise<DecoyHit[]>;
  arm(): Promise<{ armed: number }>;
  fingerprints(): string[];
}

/** Thrown after decoy callbacks and reports complete when blocking is enabled. */
export class DenyDecoyLeakError extends Error {
  readonly code = 'deny_decoy_leak';
  constructor() {
    super('A configured decoy was detected in agent-visible data.');
    this.name = 'DenyDecoyLeakError';
  }
}

interface NormalizedDecoy {
  label?: string;
  value: string;
  fingerprint: string;
  encodings: Array<{ encoding: Exclude<DecoyEncoding, 'spaced'>; variants: string[] }>;
}

const DEFAULT_API_BASE_URL = 'https://deny.sh/api';
const DEFAULT_REPORT_TIMEOUT_MS = 3000;
const DECOY_SOURCE = 'deny-sh-integrations-core/0.2.0';

function decoyFingerprint(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function normalizeDecoy(entry: string | { label?: string; value: string }): NormalizedDecoy {
  const value = typeof entry === 'string' ? entry : entry.value;
  const label = typeof entry === 'string' ? undefined : entry.label;
  if (typeof value !== 'string' || value.length < 8) {
    throw new DenyToolError('deny_config_error', 'Every decoy value must be a string of at least 8 characters.');
  }
  const base64 = Buffer.from(value, 'utf8').toString('base64');
  const base64urlPadded = base64.replace(/\+/g, '-').replace(/\//g, '_');
  const percent = encodeURIComponent(value);
  return {
    label,
    value,
    fingerprint: decoyFingerprint(value),
    encodings: [
      { encoding: 'plain', variants: [value] },
      { encoding: 'base64', variants: [...new Set([base64, base64.replace(/=+$/, '')])] },
      {
        encoding: 'base64url',
        variants: [...new Set([base64urlPadded, base64urlPadded.replace(/=+$/, '')])],
      },
      { encoding: 'hex', variants: [Buffer.from(value, 'utf8').toString('hex')] },
      ...(percent === value
        ? []
        : [{ encoding: 'percent' as const, variants: [percent] }]),
    ],
  };
}

function matchingEncoding(value: unknown, decoy: NormalizedDecoy): DecoyEncoding | undefined {
  for (const candidate of decoy.encodings) {
    const matched = valueContains(
      value,
      (text) =>
        candidate.encoding === 'hex'
          ? candidate.variants.some((variant) => text.toLowerCase().includes(variant))
          : candidate.variants.some((variant) => text.includes(variant)),
      new WeakSet(),
    );
    if (matched) return candidate.encoding;
  }
  if (
    !/\s/.test(decoy.value) &&
    valueContains(value, (text) => text.replace(/\s/g, '').includes(decoy.value), new WeakSet())
  ) {
    return 'spaced';
  }
  return undefined;
}

async function settleWithin<T>(promise: Promise<T>, timeoutMs: number): Promise<T | undefined> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<undefined>((resolve) => {
        timeout = setTimeout(() => resolve(undefined), timeoutMs);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

/**
 * Build a decoy detector for values crossing an agent boundary.
 *
 * Detection only sees values passed to `scan` or `check`. It does not detect a
 * decoy split across separate messages, embedded part-way inside a larger
 * encoded blob, or otherwise transformed beyond the documented encodings.
 */
export function createDecoyWatch(config: DecoyWatchConfig): DecoyWatch {
  if (!config || !Array.isArray(config.decoys)) {
    throw new DenyToolError('deny_config_error', '`decoys` must be an array.');
  }
  const byFingerprint = new Map<string, NormalizedDecoy>();
  for (const entry of config.decoys) {
    const decoy = normalizeDecoy(entry);
    if (!byFingerprint.has(decoy.fingerprint)) byFingerprint.set(decoy.fingerprint, decoy);
  }
  const decoys = [...byFingerprint.values()];
  const clientOptions = config.clientOptions ?? {};
  const apiKey = clientOptions.apiKey ?? process.env.DENY_API_KEY;
  const baseUrl = (clientOptions.baseUrl ?? process.env.DENY_API_URL ?? DEFAULT_API_BASE_URL).replace(
    /\/+$/,
    '',
  );
  // Tripwire routes are served at the origin; vault routes remain under /api.
  const v1Base = baseUrl.replace(/\/api$/, '');
  const shouldReport = config.report ?? Boolean(apiKey);
  const shouldBlock = config.block !== false;
  const fetchImpl = config.fetch ?? globalThis.fetch;
  const reportTimeoutMs = config.reportTimeoutMs ?? DEFAULT_REPORT_TIMEOUT_MS;
  if (!Number.isFinite(reportTimeoutMs) || reportTimeoutMs <= 0) {
    throw new DenyToolError('deny_config_error', '`reportTimeoutMs` must be a positive number.');
  }

  const scan = (value: unknown, surface: DecoySurface = 'other'): DecoyHit[] => {
    const hits: DecoyHit[] = [];
    for (const decoy of decoys) {
      const encoding = matchingEncoding(value, decoy);
      if (encoding) {
        hits.push({
          ...(decoy.label === undefined ? {} : { label: decoy.label }),
          fingerprint: decoy.fingerprint,
          surface,
          encoding,
        });
      }
    }
    return hits;
  };

  const post = async (path: string, body: Record<string, unknown>): Promise<Response> => {
    if (!apiKey) {
      throw new DenyToolError('deny_config_error', 'An API key is required for decoy reporting or arming.');
    }
    if (!fetchImpl) {
      throw new DenyToolError('deny_config_error', 'No fetch implementation is available.');
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), reportTimeoutMs);
    timeout.unref?.();
    const externalSignal = clientOptions.signal;
    const abortFromExternal = () => controller.abort(externalSignal?.reason);
    if (externalSignal?.aborted) abortFromExternal();
    else externalSignal?.addEventListener('abort', abortFromExternal, { once: true });
    try {
      return await fetchImpl(`${v1Base}${path}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
      externalSignal?.removeEventListener('abort', abortFromExternal);
    }
  };

  const notifyReportError = async (
    info: Parameters<NonNullable<DecoyWatchConfig['onReportError']>>[0],
  ): Promise<void> => {
    try {
      await config.onReportError?.(info);
    } catch {
      // Error-observer failures must never disrupt the agent path.
    }
  };

  const reportErrorText = (error: unknown): string => {
    let text = 'network_error';
    try {
      if (error instanceof Error && error.message) text = error.message;
      else if (typeof error === 'string' && error) text = error;
    } catch {
      // Retain the stable fallback.
    }
    for (const decoy of decoys) text = text.split(decoy.value).join('[deny:redacted]');
    return text;
  };

  const reportHit = async (hit: DecoyHit): Promise<void> => {
    if (!shouldReport) return;
    try {
      const response = await settleWithin(
        post('/v1/decoy-tripwires/observe', {
          tripwire_hash: hit.fingerprint,
          surface: hit.surface,
          source: DECOY_SOURCE,
        }),
        reportTimeoutMs,
      );
      if (!response) {
        await notifyReportError({
          fingerprint: hit.fingerprint,
          surface: hit.surface,
          error: 'timeout',
        });
      } else if (!response.ok) {
        await notifyReportError({
          fingerprint: hit.fingerprint,
          surface: hit.surface,
          status: response.status,
        });
      }
    } catch (error) {
      await notifyReportError({
        fingerprint: hit.fingerprint,
        surface: hit.surface,
        error: reportErrorText(error),
      });
    }
  };

  return {
    scan,
    async check(value: unknown, surface: DecoySurface = 'other'): Promise<DecoyHit[]> {
      const hits = scan(value, surface);
      await Promise.all(
        hits.map(async (hit) => {
          const onLeak = async (): Promise<void> => {
            try {
              await config.onLeak?.(hit);
            } catch {
              // User callback failures must never disrupt the agent path.
            }
          };
          await Promise.all([
            settleWithin(onLeak(), reportTimeoutMs),
            reportHit(hit),
          ]);
        }),
      );
      if (shouldBlock && hits.length > 0) throw new DenyDecoyLeakError();
      return hits;
    },
    async arm(): Promise<{ armed: number }> {
      for (const decoy of decoys) {
        const response = await post('/v1/decoy-tripwires', {
          tripwire_hash: decoy.fingerprint,
          tripwire_kind: 'plaintext',
          ...(decoy.label === undefined ? {} : { label: decoy.label }),
        });
        if (!response.ok) {
          throw new DenyToolError(
            'deny_http_error',
            `deny.sh returned ${response.status} while arming a decoy tripwire.`,
          );
        }
      }
      return { armed: decoys.length };
    },
    fingerprints(): string[] {
      return decoys.map((decoy) => decoy.fingerprint);
    },
  };
}

/** Scrub a string of every occurrence of the secret (for error messages). */
function scrub(text: string, secret: string): string {
  if (!secret) return text;
  return text.split(secret).join('[deny:redacted]');
}

/**
 * Build the framework-agnostic resolver. Adapters call this and wrap the
 * returned async function in their framework's tool interface.
 *
 * The returned function takes the validated tool args and returns the narrowed
 * DTO. It NEVER returns or throws the raw secret.
 */
export function createVaultResolver<TArgs = unknown, TResult = unknown>(
  config: DenyVaultResolverConfig<TArgs, TResult>,
): (args: TArgs) => Promise<TResult> {
  const { label, id, password, clientOptions, use } = config;
  const leakSweep = config.leakSweep !== false;
  const client = config.client ?? DEFAULT_CLIENT;

  if (!label && !id) {
    throw new DenyToolError('deny_config_error', 'Provide either `label` or `id` for the vault entry.');
  }
  if (label && id) {
    throw new DenyToolError('deny_config_error', 'Provide only ONE of `label` or `id`, not both.');
  }
  if (!password || typeof password !== 'string') {
    throw new DenyToolError('deny_config_error', '`password` is required (the vault wrap password).');
  }
  if (typeof use !== 'function') {
    throw new DenyToolError('deny_config_error', '`use(secret, args)` callback is required.');
  }

  return async function resolve(args: TArgs): Promise<TResult> {
    let secret: string;
    try {
      secret =
        id != null
          ? await client.vaultGetById(id, password, clientOptions as Record<string, unknown>)
          : await client.vaultGet(label as string, password, clientOptions as Record<string, unknown>);
    } catch (err) {
      // VaultError from deny-sh/client never contains the password or plaintext,
      // but scrub defensively and never re-throw a secret-bearing stack.
      const code = (err as { code?: string })?.code ?? 'vault_error';
      const msg = (err as Error)?.message ?? 'Vault fetch failed.';
      throw new DenyToolError(code, scrub(msg, password), undefined);
    }

    let result: TResult;
    try {
      result = await use(secret, args);
    } catch (err) {
      // The user's privileged call failed. Scrub the secret out of any message
      // or stack so a thrown upstream error can't smuggle the credential to the
      // model as a tool error.
      const msg = (err as Error)?.message ?? 'Tool execution failed.';
      throw new DenyToolError('deny_use_failed', scrub(msg, secret), undefined);
    }

    if (leakSweep) {
      if (containsSecret(result, secret, new WeakSet())) {
        // FAIL CLOSED. Return nothing; the secret never crosses the boundary.
        throw new DenyLeakError(
          'The value returned by use() contained the raw credential. ' +
            'Return a narrowed DTO that excludes the secret. (deny.sh leak sweep, fail-closed)',
        );
      }
    }

    return result;
  };
}

/** Convenience: true if the value would pass the leak sweep for `secret`. */
export function isNarrowed(value: unknown, secret: string): boolean {
  return !containsSecret(value, secret, new WeakSet());
}
