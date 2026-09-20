import { normalizers as normalize } from "@trebired/utils";
import type { AttemptPolicy, AttemptState } from "#hfap0x87te96";
import { durationToMs } from "#tncys3cufz3c";

type Entry = { count: number; startedAt: number };

function allowed(): AttemptState {
  return { blocked: false, remaining: 0, retryAfterMs: 0 };
}

function createAttemptLimiter(policy: AttemptPolicy) {
  const windowMs = durationToMs(policy.window);
  const maxAttempts = Math.max(0, Number(policy.maxAttempts) || 0);
  const entries = new Map<string, Entry>();

  function prune(now = Date.now()) {
    for (const [key, entry] of entries) if (entry.startedAt + windowMs <= now) entries.delete(key);
  }

  function read(keyInput: unknown): AttemptState {
    const key = normalize.toString(keyInput);
    if (!key || !maxAttempts || windowMs <= 0) return allowed();
    const now = Date.now();
    prune(now);
    const entry = entries.get(key);
    if (!entry) return { blocked: false, remaining: maxAttempts, retryAfterMs: 0 };
    return {
      blocked: entry.count >= maxAttempts,
      remaining: Math.max(0, maxAttempts - entry.count),
      retryAfterMs: Math.max(0, entry.startedAt + windowMs - now),
    };
  }

  function fail(keyInput: unknown): AttemptState {
    const key = normalize.toString(keyInput);
    if (!key || !maxAttempts || windowMs <= 0) return allowed();
    const now = Date.now();
    const entry = entries.get(key);
    if (!entry || entry.startedAt + windowMs <= now) entries.set(key, { count: 1, startedAt: now });
    else entries.set(key, { count: entry.count + 1, startedAt: entry.startedAt });
    return read(key);
  }

  return {
    clear: (keyInput: unknown) => entries.delete(normalize.toString(keyInput)),
    fail,
    prune,
    read,
    reset: () => entries.clear(),
  };
}

type AttemptLimiter = ReturnType<typeof createAttemptLimiter>;

export { createAttemptLimiter };
export type { AttemptLimiter };
