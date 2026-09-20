import { normalizers as normalize } from "@trebired/utils";
import type { AuthConfig, AuthStore, AuthSubject, PermissionCheckScope } from "./types.js";
import { checkPassword, hashPassword, verifyPassword } from "./credentials/index.js";
import { createCodeManager } from "./codes/index.js";
import { createPermissionEngine } from "./permissions/index.js";
import { createSessionManager, isSessionExpired } from "./sessions/index.js";
import { createTwoFactorManager } from "./twofactor/index.js";
import { createSignInFlow, type SignInResult } from "./flow.js";
import { normalizeAuthConfig } from "./config/index.js";
import { readAuthState } from "./state/index.js";
import { sessionCookieOptions, signSessionToken, verifySessionToken } from "./tokens/index.js";

type AuthOptions = {
  config?: Parameters<typeof normalizeAuthConfig>[0];
  secret: string;
  store: AuthStore;
};

function createAuth(options: AuthOptions) {
  const config: AuthConfig = normalizeAuthConfig(options && options.config);
  const secret = normalize.toString(options && options.secret);
  const store = options.store;
  const sessions = createSessionManager(store, config.session);
  const twoFactor = createTwoFactorManager(store, config.twoFactor);
  const codes = createCodeManager(store, config.codes, config.password);
  const permissions = createPermissionEngine(config.permissions);
  const { authenticate, signIn, startSession } = createSignInFlow({ config, secret, sessions, store, twoFactor });

  async function setPassword(subject: AuthSubject, password: string) {
    const check = checkPassword(password, config.password);
    if (!check.ok) return check;
    const state = readAuthState(subject);
    const passwordHash = await hashPassword(password, config.password);
    await store.saveAuthState(subject.id, { ...state, passwordHash });
    return check;
  }

  function can(subject: AuthSubject | null, permission: unknown, scope: PermissionCheckScope) {
    return permissions.can(subject, permission, scope);
  }

  return {
    authenticate,
    can,
    checkPassword: (password: unknown) => checkPassword(password, config.password),
    codes,
    config,
    cookieOptions: (secure: boolean) => sessionCookieOptions(config.session, secure),
    permissions,
    sessions,
    setPassword,
    signIn,
    signOut: (subject: AuthSubject, sessionId: unknown) => sessions.revoke(subject, sessionId),
    startSession,
    twoFactor,
  };
}

type Auth = ReturnType<typeof createAuth>;

export { createAuth };
export { createMemoryStore } from "./store/index.js";
export { checkPassword, hashPassword, verifyPassword } from "./credentials/index.js";
export { createPermissionEngine } from "./permissions/index.js";
export { isSessionExpired } from "./sessions/index.js";
export { normalizeAuthConfig } from "./config/index.js";
export { readAuthState } from "./state/index.js";
export { durationToMs, sessionCookieOptions, signSessionToken, verifySessionToken } from "./tokens/index.js";
export *from "./twofactor/totp.js";
export *from "./permissions/keys.js";
export type { Auth, AuthOptions, SignInResult };
export type *from "./types.js";
