import { normalizers as normalize } from "@trebired/utils";
import type { AuthStore, AuthSubject, StoredAuthState } from "#hfap0x87te96";
import { normalizeAuthState } from "#l04g1rbs8bmx";

function createMemoryStore(seed: AuthSubject[] = []): AuthStore& { subjects: Map<string, AuthSubject> } {
  const subjects = new Map<string, AuthSubject>();
  for (const subject of seed) {
    const id = normalize.toString(subject && subject.id);
    if (id) subjects.set(id, { ...subject, auth: normalizeAuthState(subject.auth) });
  }

  return {
    async findSubjectByIdentifier(identifier: string) {
      const wanted = normalize.toString(identifier).trim().toLowerCase();
      if (!wanted) return null;
      for (const subject of subjects.values()) {
        const record = subject as Record<string, unknown>;
        const candidates = [record.id, record.username, record.email].map((value) =>
          normalize.toString(value).trim().toLowerCase(),
        );
        if (candidates.includes(wanted)) return subject;
      }
      return null;
    },
    async loadSubject(id: string) {
      return subjects.get(normalize.toString(id)) || null;
    },
    async saveAuthState(id: string, state: StoredAuthState) {
      const subjectId = normalize.toString(id);
      const subject = subjects.get(subjectId);
      if (!subject) return false;
      subjects.set(subjectId, { ...subject, auth: normalizeAuthState(state) });
      return true;
    },
    subjects,
  };
}

export { createMemoryStore };
