import { generateId, normalizers as normalize } from "@trebired/utils";
import type { AuthStore, AuthSubject, SessionPolicy, SessionRecord, StoredAuthState } from "#hfap0x87te96";
import { describeDevice, normalizeSessionDevice } from "./device.js";
import { durationToMs } from "#tncys3cufz3c";
import { readAuthState } from "#l04g1rbs8bmx";

type SessionContext = {
  device?: unknown;
  headers?: Record<string, unknown>|null;
  ip?: string;
  locale?: string;
};

function nowIso() {
  return new Date().toISOString();
}

function sortSessions(sessions: SessionRecord[]) {
  return sessions.slice().sort((left, right) => String(right.lastSeenAt).localeCompare(String(left.lastSeenAt)));
}

function trimSessions(sessions: SessionRecord[], policy: SessionPolicy, keepId = "") {
  const sorted = sortSessions(sessions);
  if (sorted.length <= policy.maxPerSubject) return sorted;
  const kept = sorted.filter((entry) => entry.id === keepId);
  for (const entry of sorted) {
    if (kept.length >= policy.maxPerSubject) break;
    if (entry.id !== keepId) kept.push(entry);
  }
  return sortSessions(kept);
}

function buildSession(context: SessionContext, policy: SessionPolicy): SessionRecord {
  const createdAt = nowIso();
  const ttl = durationToMs(policy.ttl);
  return {
    createdAt,
    device: context && context.device ? normalizeSessionDevice(context.device) : describeDevice(context && context.headers),
    expiresAt: ttl > 0 ? new Date(Date.parse(createdAt) + ttl).toISOString() : "",
    id: String(generateId("numeric")),
    ip: normalize.toString(context && context.ip),
    lastSeenAt: createdAt,
    locale: normalize.toString(context && context.locale),
  };
}

function isSessionExpired(session: SessionRecord | null, policy: SessionPolicy) {
  if (!session) return true;
  const expiry = Date.parse(session.expiresAt || "");
  if (Number.isFinite(expiry) && expiry <= Date.now()) return true;
  const idle = durationToMs(policy.idleTimeout);
  if (!idle) return false;
  const lastSeen = Date.parse(session.lastSeenAt || session.createdAt || "");
  return Number.isFinite(lastSeen) && lastSeen + idle <= Date.now();
}

function findSession(state: StoredAuthState, sessionId: unknown) {
  const id = normalize.toString(sessionId);
  return id ? state.sessions.find((entry) => entry.id === id) || null : null;
}

function createSessionManager(store: AuthStore, policy: SessionPolicy) {
  async function write(subject: AuthSubject, state: StoredAuthState, sessions: SessionRecord[], keepId = "") {
    return await store.saveAuthState(subject.id, { ...state, sessions: trimSessions(sessions, policy, keepId) });
  }

  return {
    async clear(subject: AuthSubject, keepSessionId: unknown = "") {
      const state = readAuthState(subject);
      const keepId = normalize.toString(keepSessionId);
      const kept = keepId ? state.sessions.filter((entry) => entry.id === keepId) : [];
      return await write(subject, state, kept, keepId);
    },
    async list(subject: AuthSubject) {
      return sortSessions(readAuthState(subject).sessions);
    },
    async open(subject: AuthSubject, context: SessionContext = {}) {
      const state = readAuthState(subject);
      const session = buildSession(context, policy);
      const saved = await write(subject, state, [session, ...state.sessions], session.id);
      return saved ? session : null;
    },
    async revoke(subject: AuthSubject, sessionId: unknown) {
      const state = readAuthState(subject);
      const id = normalize.toString(sessionId);
      const sessions = state.sessions.filter((entry) => entry.id !== id);
      if (sessions.length === state.sessions.length) return false;
      return await write(subject, state, sessions);
    },
    async touch(subject: AuthSubject, sessionId: unknown) {
      const state = readAuthState(subject);
      const current = findSession(state, sessionId);
      if (!current || isSessionExpired(current, policy)) return null;
      const lastSeenAt = nowIso();
      const sessions = state.sessions.map((entry) => (entry.id === current.id ? { ...entry, lastSeenAt } : entry));
      const saved = await write(subject, state, sessions, current.id);
      return saved ? { ...current, lastSeenAt } : null;
    },
  };
}

export { buildSession, createSessionManager, findSession, isSessionExpired, sortSessions, trimSessions };
export type { SessionContext };
