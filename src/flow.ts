import { normalizers as normalize } from "@trebired/utils";
import type { AuthConfig, AuthStore, AuthSubject, SessionRecord } from "#hfap0x87te96";
import { createAttemptLimiter } from "./attempts/index.js";
import type { SessionContext, createSessionManager } from "./sessions/index.js";
import type { createTwoFactorManager } from "./twofactor/index.js";
import { readAuthState } from "./state/index.js";
import { signSessionToken, verifySessionToken } from "./tokens/index.js";
import { verifyPassword } from "./credentials/index.js";

type SignInResult = {
  reason: "invalid-credentials" | "rate-limited" | "two-factor-required" | "ok";
  retryAfterMs?: number;
  session: SessionRecord | null;
  subject: AuthSubject | null;
  token: string;
};

type FlowInput = {
  config: AuthConfig;
  secret: string;
  sessions: ReturnType<typeof createSessionManager>;
  store: AuthStore;
  twoFactor: ReturnType<typeof createTwoFactorManager>;
};

function createSignInFlow(input: FlowInput) {
  const { config, secret, sessions, store, twoFactor } = input;
  const attempts = createAttemptLimiter(config.login);

  function attemptKey(identifier: unknown, context: SessionContext) {
    return normalize.toString(context && context.ip) || normalize.toString(identifier).trim().toLowerCase();
  }

  async function startSession(subject: AuthSubject, context: SessionContext = {}): Promise<SignInResult> {
    const session = await sessions.open(subject, context);
    if (!session) return { reason: "invalid-credentials", session: null, subject, token: "" };
    const token = signSessionToken({ sessionId: session.id, subjectId: subject.id }, secret, config.session);
    return { reason: "ok", session, subject, token };
  }

  async function signIn(identifier: string, password: string, context: SessionContext = {}): Promise<SignInResult> {
    const key = attemptKey(identifier, context);
    const limit = attempts.read(key);
    if (limit.blocked) {
      return { reason: "rate-limited", retryAfterMs: limit.retryAfterMs, session: null, subject: null, token: "" };
    }
    const subject = await findSubject(identifier, password);
    if (!subject) {
      attempts.fail(key);
      return { reason: "invalid-credentials", session: null, subject: null, token: "" };
    }
    attempts.clear(key);
    if (twoFactor.isEnabled(subject)) return { reason: "two-factor-required", session: null, subject, token: "" };
    return await startSession(subject, context);
  }

  async function findSubject(identifier: string, password: string) {
    const lookup = store.findSubjectByIdentifier;
    const subject = lookup ? await lookup(identifier) : null;
    if (!subject) {
      await verifyPassword(password, "");
      return null;
    }
    return (await verifyPassword(password, readAuthState(subject).passwordHash)) ? subject : null;
  }

  async function authenticate(token: unknown) {
    const claims = verifySessionToken(token, secret);
    if (!claims) return null;
    const subject = await store.loadSubject(claims.subjectId);
    if (!subject) return null;
    const session = await sessions.touch(subject, claims.sessionId);
    return session ? { session, subject } : null;
  }

  return { attempts, authenticate, signIn, startSession };
}

export { createSignInFlow };
export type { SignInResult };
