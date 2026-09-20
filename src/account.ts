import { normalizers as normalize } from "@trebired/utils";
import type { AuthConfig, AuthStore, AuthSubject } from "#hfap0x87te96";
import type { createCodeManager } from "./codes/index.js";
import { checkPassword, hashPassword, verifyPassword } from "./credentials/index.js";
import { readAuthState } from "./state/index.js";

type AccountInput = {
  codes: ReturnType<typeof createCodeManager>;
  config: AuthConfig;
  store: AuthStore;
};

type ChangeOptions = {
  keepSessionId?: string;
  revokeOtherSessions?: boolean;
};

type ChangeResult = {
  failed: string[];
  ok: boolean;
  reason: "invalid-password" | "reused-password" | "weak-password" | "ok";
};

function createAccountFlow(input: AccountInput) {
  const { codes, config, store } = input;

  async function setPassword(subject: AuthSubject, password: string) {
    const check = checkPassword(password, config.password);
    if (!check.ok) return check;
    const state = readAuthState(subject);
    const passwordHash = await hashPassword(password, config.password);
    await store.saveAuthState(subject.id, { ...state, passwordHash });
    return check;
  }

  async function changePassword(
    subject: AuthSubject,
    currentPassword: string,
    nextPassword: string,
    options: ChangeOptions = {},
  ): Promise<ChangeResult> {
    const state = readAuthState(subject);
    if (!(await verifyPassword(currentPassword, state.passwordHash))) {
      return { failed: [], ok: false, reason: "invalid-password" };
    }
    if (await verifyPassword(nextPassword, state.passwordHash)) {
      return { failed: [], ok: false, reason: "reused-password" };
    }
    const check = checkPassword(nextPassword, config.password);
    if (!check.ok) return { failed: check.failed, ok: false, reason: "weak-password" };
    const keepId = normalize.toString(options.keepSessionId);
    const kept = options.revokeOtherSessions ? state.sessions.filter((entry) => entry.id === keepId) : state.sessions;
    const passwordHash = await hashPassword(nextPassword, config.password);
    await store.saveAuthState(subject.id, { ...state, passwordHash, sessions: kept });
    return { failed: [], ok: true, reason: "ok" };
  }

  async function revealBackupCode(subject: AuthSubject, password: string) {
    const state = readAuthState(subject);
    if (!(await verifyPassword(password, state.passwordHash))) return null;
    return await codes.revealBackupCode(subject);
  }

  return { changePassword, revealBackupCode, setPassword };
}

export { createAccountFlow };
export type { ChangeOptions, ChangeResult };
