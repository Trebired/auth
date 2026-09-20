import type { AuthConfig, AuthStore, AuthSubject, SessionRecord } from "#hfap0x87te96";
import type { SessionContext, createSessionManager } from "./sessions/index.js";
import type { createTwoFactorManager } from "./twofactor/index.js";
import { readAuthState } from "./state/index.js";
import { signSessionToken, verifySessionToken } from "./tokens/index.js";
import { verifyPassword } from "./credentials/index.js";

type SignInResult = {
  reason: "invalid-credentials" | "two-factor-required" | "ok";
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

  async function startSession(subject: AuthSubject, context: SessionContext = {}): Promise<SignInResult> {
    const session = await sessions.open(subject, context);
    if (!session) return { reason: "invalid-credentials", session: null, subject, token: "" };
    const token = signSessionToken({ sessionId: session.id, subjectId: subject.id }, secret, config.session);
    return { reason: "ok", session, subject, token };
  }

  async function signIn(identifier: string, password: string, context: SessionContext = {}): Promise<SignInResult> {
    const failed: SignInResult = { reason: "invalid-credentials", session: null, subject: null, token: "" };
    const lookup = store.findSubjectByIdentifier;
    const subject = lookup ? await lookup(identifier) : null;
    if (!subject) {
      await verifyPassword(password, "");
      return failed;
    }
    if (!(await verifyPassword(password, readAuthState(subject).passwordHash))) return failed;
    if (twoFactor.isEnabled(subject)) return { reason: "two-factor-required", session: null, subject, token: "" };
    return await startSession(subject, context);
  }

  async function authenticate(token: unknown) {
    const claims = verifySessionToken(token, secret);
    if (!claims) return null;
    const subject = await store.loadSubject(claims.subjectId);
    if (!subject) return null;
    const session = await sessions.touch(subject, claims.sessionId);
    return session ? { session, subject } : null;
  }

  return { authenticate, signIn, startSession };
}

export { createSignInFlow };
export type { SignInResult };
