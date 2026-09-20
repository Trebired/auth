import crypto from "node:crypto";
import { normalizers as normalize } from "@trebired/utils";
import type { AuthStore, AuthSubject, CodePolicy } from "#hfap0x87te96";
import { durationToMs } from "#tncys3cufz3c";
import { hashPassword, verifyPassword } from "#8975r0zvphjw";
import { readAuthState } from "#l04g1rbs8bmx";
import type { PasswordPolicy } from "#hfap0x87te96";

function generateCode(policy: CodePolicy) {
  const alphabet = policy.alphabet || "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.randomBytes(policy.length);
  let code = "";
  for (let index = 0; index < policy.length; index += 1) code += alphabet[bytes[index] % alphabet.length];
  return code;
}

function codeExpiry(policy: CodePolicy) {
  const ttl = durationToMs(policy.ttl);
  return ttl > 0 ? new Date(Date.now() + ttl).toISOString() : "";
}

function codeIsExpired(expiresAt: unknown) {
  const expiry = Date.parse(normalize.toString(expiresAt));
  return Number.isFinite(expiry) && expiry <= Date.now();
}

function createActivationQueries() {
  function state(subject: AuthSubject) {
    return readAuthState(subject).activation;
  }

  function usable(stored: ReturnType<typeof state>) {
    return Boolean(stored.code) && !stored.usedAt && !codeIsExpired(stored.expiresAt);
  }

  return {
    activationState(subject: AuthSubject) {
      const stored = state(subject);
      return {
        code: stored.code,
        expired: Boolean(stored.code) && codeIsExpired(stored.expiresAt),
        issued: Boolean(stored.code),
        used: Boolean(stored.usedAt),
      };
    },
    matchesActivationCode(subject: AuthSubject, input: unknown) {
      const stored = state(subject);
      const code = normalize.toString(input).trim().toUpperCase();
      return Boolean(code) && usable(stored) && stored.code.toUpperCase() === code;
    },
    needsActivation(subject: AuthSubject) {
      return usable(state(subject));
    },
  };
}

function createBackupCodes(store: AuthStore, policy: CodePolicy, password: PasswordPolicy) {
  return {
    async issueBackupCode(subject: AuthSubject) {
      const state = readAuthState(subject);
      const code = generateCode(policy);
      const saved = await store.saveAuthState(subject.id, {
          ...state,
          backupCode: { hash: await hashPassword(code, password), lastUsedAt: "", revealCount: 0, secret: code },
      });
      return saved ? code : null;
    },
    async redeemBackupCode(subject: AuthSubject, input: unknown) {
      const state = readAuthState(subject);
      const code = normalize.toString(input).trim().toUpperCase();
      if (!code || !state.backupCode.hash) return false;
      if (!(await verifyPassword(code, state.backupCode.hash))) return false;
      return await store.saveAuthState(subject.id, {
          ...state,
          backupCode: { hash: "", lastUsedAt: new Date().toISOString(), revealCount: state.backupCode.revealCount, secret: "" },
      });
    },
    async revealBackupCode(subject: AuthSubject) {
      const state = readAuthState(subject);
      if (!state.backupCode.secret) return null;
      const revealCount = state.backupCode.revealCount + 1;
      const saved = await store.saveAuthState(subject.id, { ...state, backupCode: { ...state.backupCode, revealCount } });
      return saved ? { code: state.backupCode.secret, revealCount } : null;
    },
  };
}

function createCodeManager(store: AuthStore, codes: { activation: CodePolicy; backup: CodePolicy }, password: PasswordPolicy) {
  return {
    ...createActivationQueries(),
    ...createBackupCodes(store, codes.backup, password),
    async issueActivationCode(subject: AuthSubject) {
      const state = readAuthState(subject);
      const code = generateCode(codes.activation);
      const saved = await store.saveAuthState(subject.id, {
          ...state,
          activation: { code, createdAt: new Date().toISOString(), expiresAt: codeExpiry(codes.activation), usedAt: "" },
      });
      return saved ? code : null;
    },
    async redeemActivationCode(subject: AuthSubject, input: unknown) {
      const state = readAuthState(subject);
      const code = normalize.toString(input).trim().toUpperCase();
      const stored = state.activation;
      if (!code || !stored.code || stored.usedAt || codeIsExpired(stored.expiresAt)) return false;
      if (stored.code.toUpperCase() !== code) return false;
      return await store.saveAuthState(subject.id, {
          ...state,
          activation: { ...stored, usedAt: new Date().toISOString() },
      });
    },
  };
}

export { codeIsExpired, createCodeManager, generateCode };
