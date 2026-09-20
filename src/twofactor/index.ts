import { normalizers as normalize } from "@trebired/utils";
import type { AuthStore, AuthSubject, StoredAuthState, TwoFactorPolicy } from "#hfap0x87te96";
import { durationToMs } from "#tncys3cufz3c";
import { generateSecret, otpauthUrl, verifyTotp } from "./totp.js";
import { readAuthState } from "#l04g1rbs8bmx";

function nowIso() {
  return new Date().toISOString();
}

function pendingExpiry(policy: TwoFactorPolicy) {
  const ttl = durationToMs(policy.pendingTtl);
  return ttl > 0 ? new Date(Date.now() + ttl).toISOString() : "";
}

function pendingIsUsable(state: StoredAuthState) {
  if (!state.twoFactor.pendingSecret) return false;
  const expiry = Date.parse(state.twoFactor.pendingExpiresAt || "");
  return !Number.isFinite(expiry) || expiry > Date.now();
}

async function beginSetup(
  save: (subject: AuthSubject, state: StoredAuthState, twoFactor: StoredAuthState["twoFactor"]) => Promise<boolean>,
  policy: TwoFactorPolicy,
  subject: AuthSubject,
  accountLabel: string,
) {
  const state = readAuthState(subject);
  if (state.twoFactor.enabled) return null;
  const secret = generateSecret(policy);
  const saved = await save(subject, state, {
      ...state.twoFactor,
      pendingExpiresAt: pendingExpiry(policy),
      pendingSecret: secret,
  });
  if (!saved) return null;
  return { otpauthUrl: otpauthUrl(secret, normalize.toString(accountLabel), policy), secret };
}

function createTwoFactorManager(store: AuthStore, policy: TwoFactorPolicy) {
  async function save(subject: AuthSubject, state: StoredAuthState, twoFactor: StoredAuthState["twoFactor"]) {
    return await store.saveAuthState(subject.id, { ...state, twoFactor });
  }

  return {
    begin: (subject: AuthSubject, accountLabel: string) => beginSetup(save, policy, subject, accountLabel),
    async confirm(subject: AuthSubject, code: unknown) {
      const state = readAuthState(subject);
      if (!pendingIsUsable(state)) return false;
      if (!verifyTotp(state.twoFactor.pendingSecret, code, policy)) return false;
      return await save(subject, state, {
          disabledAt: "",
          enabled: true,
          enabledAt: nowIso(),
          pendingExpiresAt: "",
          pendingSecret: "",
          secret: state.twoFactor.pendingSecret,
      });
    },
    async disable(subject: AuthSubject) {
      const state = readAuthState(subject);
      if (!state.twoFactor.enabled) return false;
      return await save(subject, state, {
          disabledAt: nowIso(),
          enabled: false,
          enabledAt: state.twoFactor.enabledAt,
          pendingExpiresAt: "",
          pendingSecret: "",
          secret: "",
      });
    },
    isEnabled(subject: AuthSubject) {
      return readAuthState(subject).twoFactor.enabled === true;
    },
    verify(subject: AuthSubject, code: unknown) {
      const state = readAuthState(subject);
      if (!state.twoFactor.enabled || !state.twoFactor.secret) return false;
      return verifyTotp(state.twoFactor.secret, code, policy);
    },
  };
}

export { createTwoFactorManager, pendingIsUsable };
export *from "./totp.js";
