import { normalizers as normalize } from "@trebired/utils";
import type { AuthConfig, AuthStore, AuthSubject, PermissionCheckScope, RoleProvider, SecretCipher } from "./types.js";
import { checkPassword } from "./credentials/index.js";
import { createCodeManager } from "./codes/index.js";
import { createPermissionEngine } from "./permissions/index.js";
import { createSessionManager, isSessionExpired } from "./sessions/index.js";
import { createTwoFactorManager } from "./twofactor/index.js";
import { createAccountFlow } from "./account.js";
import { createSignInFlow, type SignInResult } from "./flow.js";
import { normalizeAuthConfig } from "./config/index.js";
import { createProtectedStore, revealState } from "./store/protected.js";
import { createSecretCipher } from "./crypto/index.js";
import { readAuthState } from "./state/index.js";
import { sessionCookieOptions, signSessionToken, verifySessionToken } from "./tokens/index.js";

type AuthOptions = {
  cipher?: SecretCipher | null;
  config?: Parameters<typeof normalizeAuthConfig>[0];
  encryptionKey?: string;
  roles?: RoleProvider | null;
  secret: string;
  store: AuthStore;
};

function readCipher(options: AuthOptions): SecretCipher | null {
  if (options.cipher && typeof options.cipher.encrypt === "function") return options.cipher;
  const key = normalize.toString(options.encryptionKey);
  return key ? createSecretCipher(key) : null;
}

function createAuth(options: AuthOptions) {
  const config: AuthConfig = normalizeAuthConfig(options && options.config);
  const secret = normalize.toString(options && options.secret);
  const cipher = readCipher(options);
  const store = cipher ? createProtectedStore(options.store, cipher) : options.store;
  const sessions = createSessionManager(store, config.session);
  const twoFactor = createTwoFactorManager(store, config.twoFactor);
  const codes = createCodeManager(store, config.codes, config.password);
  const permissions = createPermissionEngine(config.permissions, { roleProvider: options.roles });
  const flow = createSignInFlow({ config, secret, sessions, store, twoFactor });
  const { attempts, authenticate, signIn, startSession } = flow;

  const account = createAccountFlow({ codes, config, store });

  async function can(subject: AuthSubject | null, permission: unknown, scope: PermissionCheckScope) {
    return await permissions.can(subject, permission, scope);
  }

  return {
    ...account,
    attempts,
    authenticate,
    can,
    loadSubject: (id: string) => store.loadSubject(id),
    readState: (subject: AuthSubject) => (cipher ? revealState(readAuthState(subject), cipher) : readAuthState(subject)),
    checkPassword: (password: unknown) => checkPassword(password, config.password),
    codes,
    config,
    cookieOptions: (secure: boolean) => sessionCookieOptions(config.session, secure),
    permissions,
    sessions,
    signIn,
    signOut: (subject: AuthSubject, sessionId: unknown) => sessions.revoke(subject, sessionId),
    startSession,
    twoFactor,
  };
}

type Auth = ReturnType<typeof createAuth>;

export { createAuth };
export { createAttemptLimiter } from "./attempts/index.js";
export { createMemoryStore } from "./store/index.js";
export { createProtectedStore, protectState, revealState } from "./store/protected.js";
export { createSecretCipher, isEncryptedSecret } from "./crypto/index.js";
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
