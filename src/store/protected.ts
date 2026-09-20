import { normalizers as normalize } from "@trebired/utils";
import type { AuthStore, AuthSubject, SecretCipher, StoredAuthState } from "#hfap0x87te96";
import { normalizeAuthState } from "#l04g1rbs8bmx";

function mapSecrets(state: StoredAuthState, turn: (value: string) => string): StoredAuthState {
  return {
    ...state,
    backupCode: { ...state.backupCode, secret: turn(state.backupCode.secret) },
    twoFactor: {
      ...state.twoFactor,
      pendingSecret: turn(state.twoFactor.pendingSecret),
      secret: turn(state.twoFactor.secret),
    },
  };
}

function protectState(state: StoredAuthState, cipher: SecretCipher): StoredAuthState {
  return mapSecrets(state, (value) => (value ? cipher.encrypt(value) : ""));
}

function revealState(state: StoredAuthState, cipher: SecretCipher): StoredAuthState {
  return mapSecrets(state, (value) => (value ? cipher.decrypt(value) : ""));
}

function revealSubject(subject: AuthSubject | null, cipher: SecretCipher): AuthSubject | null {
  if (!subject) return null;
  return { ...subject, auth: revealState(normalizeAuthState(subject.auth), cipher) };
}

function createProtectedStore(store: AuthStore, cipher: SecretCipher): AuthStore {
  const protectedStore: AuthStore = {
    async loadSubject(id: string) {
      return revealSubject(await store.loadSubject(id), cipher);
    },
    async saveAuthState(id: string, state: StoredAuthState) {
      return await store.saveAuthState(normalize.toString(id), protectState(normalizeAuthState(state), cipher));
    },
  };
  if (typeof store.findSubjectByIdentifier === "function") {
    protectedStore.findSubjectByIdentifier = async(identifier: string) =>
    revealSubject(await store.findSubjectByIdentifier!(identifier), cipher);
  }
  return protectedStore;
}

export { createProtectedStore, protectState, revealState };
