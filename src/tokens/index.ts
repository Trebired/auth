import jwt from "jsonwebtoken";
import { normalizers as normalize } from "@trebired/utils";
import type { SessionPolicy } from "#hfap0x87te96";

type SessionTokenClaims = {
  sessionId: string;
  subjectId: string;
};

const DURATION_UNITS: Record<string, number> = {
  d: 24 * 60 * 60 * 1000,
  h: 60 * 60 * 1000,
  m: 60 * 1000,
  ms: 1,
  s: 1000,
  w: 7 * 24 * 60 * 60 * 1000,
};

function durationToMs(input: unknown) {
  const raw = normalize.toString(input).trim().toLowerCase();
  if (!raw) return 0;
  if (/^\d+$/u.test(raw)) return Number(raw) * 1000;
  const match = raw.match(/^(\d+)(ms|s|m|h|d|w)$/u);
  if (!match) return 0;
  const value = Number(match[1]);
  return Number.isFinite(value) && value > 0 ? value * DURATION_UNITS[match[2]] : 0;
}

function signSessionToken(claims: SessionTokenClaims, secret: string, policy: SessionPolicy) {
  const subjectId = normalize.toString(claims && claims.subjectId);
  const sessionId = normalize.toString(claims && claims.sessionId);
  if (!subjectId) throw new Error("auth-token-missing-subject");
  if (!sessionId) throw new Error("auth-token-missing-session");
  if (!normalize.toString(secret)) throw new Error("auth-token-missing-secret");
  return jwt.sign({ sid: sessionId, uid: subjectId }, secret, { expiresIn: policy.ttl as any });
}

function verifySessionToken(token: unknown, secret: string): SessionTokenClaims | null {
  const raw = normalize.toString(token);
  if (!raw || !normalize.toString(secret)) return null;
  try {
    const payload = jwt.verify(raw, secret) as Record<string, unknown>;
    const subjectId = normalize.toString(payload && payload.uid);
    const sessionId = normalize.toString(payload && payload.sid);
    return subjectId && sessionId ? { sessionId, subjectId } : null;
  } catch {
    return null;
  }
}

function sessionCookieOptions(policy: SessionPolicy, secure: boolean) {
  const maxAge = durationToMs(policy.ttl);
  return {
    httpOnly: true,
    path: "/",
    sameSite: "lax"as const,
    secure: secure === true,
    ...(maxAge > 0 ? { maxAge } : {}),
  };
}

export { durationToMs, sessionCookieOptions, signSessionToken, verifySessionToken };
export type { SessionTokenClaims };
