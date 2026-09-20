import { normalizers as normalize, toObject } from "@trebired/utils";
import type { SessionRecord, StoredAuthState, TwoFactorState } from "#hfap0x87te96";
import { normalizeSessionDevice } from "#tscm28xzccwy";

function emptyTwoFactor(): TwoFactorState {
  return { disabledAt: "", enabled: false, enabledAt: "", pendingExpiresAt: "", pendingSecret: "", secret: "" };
}

function normalizeTwoFactor(input: unknown): TwoFactorState {
  const source = toObject<Record<string, unknown>>(input);
  return {
    disabledAt: normalize.toString(source.disabledAt),
    enabled: source.enabled === true,
    enabledAt: normalize.toString(source.enabledAt),
    pendingExpiresAt: normalize.toString(source.pendingExpiresAt),
    pendingSecret: normalize.toString(source.pendingSecret),
    secret: normalize.toString(source.secret),
  };
}

function normalizeSession(input: unknown): SessionRecord {
  const source = toObject<Record<string, unknown>>(input);
  return {
    createdAt: normalize.toString(source.createdAt),
    device: normalizeSessionDevice(source.device),
    expiresAt: normalize.toString(source.expiresAt),
    id: normalize.toString(source.id),
    ip: normalize.toString(source.ip),
    lastSeenAt: normalize.toString(source.lastSeenAt) || normalize.toString(source.createdAt),
    locale: normalize.toString(source.locale),
  };
}

function normalizeSessions(input: unknown): SessionRecord[] {
  const list = Array.isArray(input) ? input : [];
  return list.map(normalizeSession).filter((entry) => Boolean(entry.id));
}

function normalizeAuthState(input: unknown): StoredAuthState {
  const source = toObject<Record<string, any>>(input);
  const activation = toObject<Record<string, unknown>>(source.activation);
  const backup = toObject<Record<string, unknown>>(source.backupCode);
  return {
    activation: {
      code: normalize.toString(activation.code),
      createdAt: normalize.toString(activation.createdAt),
      expiresAt: normalize.toString(activation.expiresAt),
      usedAt: normalize.toString(activation.usedAt),
    },
    backupCode: {
      hash: normalize.toString(backup.hash),
      lastUsedAt: normalize.toString(backup.lastUsedAt),
      revealCount: Math.max(0, Number(backup.revealCount) || 0),
      secret: normalize.toString(backup.secret),
    },
    passwordHash: normalize.toString(source.passwordHash),
    sessions: normalizeSessions(source.sessions),
    twoFactor: source.twoFactor ? normalizeTwoFactor(source.twoFactor) : emptyTwoFactor(),
  };
}

function readAuthState(subject: unknown): StoredAuthState {
  const source = toObject<Record<string, unknown>>(subject);
  return normalizeAuthState(source.auth);
}

export { emptyTwoFactor, normalizeAuthState, normalizeSession, normalizeSessions, readAuthState };
