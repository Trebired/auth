import { normalizers as normalize } from "@trebired/utils";
import type { Auth } from "#6bqo5aavo6oc";
import { normalizeRequirement, requirePermission, requireRole, scopeFromParam } from "./guards.js";
import type { Denial, GuardOptions, ScopeResolver } from "./guards.js";

type RequestLike = {
  cookies?: Record<string, unknown>;
  headers?: Record<string, unknown>;
  params?: Record<string, unknown>;
  [key: string]: unknown;
};

type ResponseLike = {
  clearCookie?: (name: string, options?: unknown) => unknown;
  cookie?: (name: string, value: string, options?: unknown) => unknown;
  status: (code: number) => { end: () => unknown; json: (body: unknown) => unknown };
};

function readCookie(req: RequestLike, name: string) {
  const fromParser = req && req.cookies && typeof req.cookies === "object" ? req.cookies[name] : "";
  if (normalize.toString(fromParser)) return normalize.toString(fromParser);
  const header = normalize.toString(req && req.headers && (req.headers as Record<string, unknown>).cookie);
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return "";
}

function attachViewer(auth: Auth, viewerKey = "viewer") {
  return async function authenticateRequest(req: RequestLike, _res: ResponseLike, next: () => void) {
    const token = readCookie(req, auth.config.session.cookieName);
    const authenticated = token ? await auth.authenticate(token) : null;
    (req as Record<string, unknown>)[viewerKey] = authenticated ? authenticated.subject : null;
    (req as Record<string, unknown>).authSession = authenticated ? authenticated.session : null;
    next();
  };
}

function requireAuth(viewerKey = "viewer") {
  return function requireAuthenticated(req: RequestLike, res: ResponseLike, next: () => void) {
    if ((req as Record<string, unknown>)[viewerKey]) return next();
    res.status(401).json({ error: true, status_code: "unauthorized" });
  };
}

function setSessionCookie(auth: Auth, res: ResponseLike, token: string, secure: boolean) {
  if (typeof res.cookie !== "function") return;
  res.cookie(auth.config.session.cookieName, token, auth.cookieOptions(secure));
}

function clearSessionCookie(auth: Auth, res: ResponseLike, secure: boolean) {
  if (typeof res.clearCookie !== "function") return;
  res.clearCookie(auth.config.session.cookieName, auth.cookieOptions(secure));
}

export {
  attachViewer,
  clearSessionCookie,
  normalizeRequirement,
  readCookie,
  requireAuth,
  requirePermission,
  requireRole,
  scopeFromParam,
  setSessionCookie,
};
export type { Denial, GuardOptions, RequestLike, ResponseLike, ScopeResolver };
