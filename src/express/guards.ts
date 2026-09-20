import { normalizers as normalize } from "@trebired/utils";
import type { Auth } from "#6bqo5aavo6oc";
import type { PermissionCheckScope, PermissionRequirement } from "#hfap0x87te96";
import { normalizeRoleKey } from "#putecwujbpkg";

type RequestLike = Record<string, unknown>;

type Denial = {
  permissions?: string[];
  reason: "forbidden" | "unauthorized" | "unknown-permission";
  requirement?: PermissionRequirement;
  scope?: PermissionCheckScope;
  statusCode: number;
};

type GuardOptions = {
  onDenied?: (req: RequestLike, res: ResponderLike, denial: Denial) => unknown;
  viewerKey?: string;
};

type ResponderLike = {
  status: (code: number) => { end: () => unknown; json: (body: unknown) => unknown };
};

type ScopeResolver = (req: RequestLike) => PermissionCheckScope | Promise<PermissionCheckScope>;

function normalizeRequirement(input: unknown): PermissionRequirement {
  if (typeof input === "string") return { all: [input] };
  if (Array.isArray(input)) return { all: input.map((entry) => normalize.toString(entry)).filter(Boolean) };
  const source = input && typeof input === "object" ? (input as PermissionRequirement) : {};
  const all = Array.isArray(source.all) ? source.all.map((entry) => normalize.toString(entry)).filter(Boolean) : [];
  const any = Array.isArray(source.any) ? source.any.map((entry) => normalize.toString(entry)).filter(Boolean) : [];
  return any.length ? { any } : { all };
}

function requirementPermissions(requirement: PermissionRequirement) {
  return [...(requirement.all || []), ...(requirement.any || [])];
}

function deny(req: RequestLike, res: ResponderLike, denial: Denial, options: GuardOptions) {
  if (typeof options.onDenied === "function") return options.onDenied(req, res, denial);
  return res.status(denial.statusCode).json({ error: true, status_code: denial.reason });
}

function undeclared(auth: Auth, scope: unknown, requirement: PermissionRequirement) {
  return requirementPermissions(requirement).filter((permission) => !auth.permissions.isDeclared(scope, permission));
}

function requirePermission(auth: Auth, permissionInput: unknown, resolveScope: ScopeResolver, options: GuardOptions = {}) {
  const requirement = normalizeRequirement(permissionInput);
  const viewerKey = options.viewerKey || "viewer";

  return async function requirePermitted(req: RequestLike, res: ResponderLike, next: () => void) {
    const viewer = req[viewerKey] as never;
    if (!viewer) return deny(req, res, { reason: "unauthorized", statusCode: 401 }, options);
    const scope = await resolveScope(req);
    const unknown = undeclared(auth, scope && scope.scope, requirement);
    if (unknown.length) {
      return deny(req, res, { permissions: unknown, reason: "unknown-permission", requirement, scope, statusCode: 500 }, options);
    }
    if (await auth.permissions.satisfies(viewer, requirement, scope)) return next();
    return deny(req, res, { reason: "forbidden", requirement, scope, statusCode: 403 }, options);
  };
}

function requireRole(auth: Auth, roleKeys: unknown, resolveScope: ScopeResolver, options: GuardOptions = {}) {
  const wanted = (Array.isArray(roleKeys) ? roleKeys : [roleKeys]).map((entry) => normalizeRoleKey(entry)).filter(Boolean);
  const viewerKey = options.viewerKey || "viewer";

  return async function requireRoled(req: RequestLike, res: ResponderLike, next: () => void) {
    const viewer = req[viewerKey] as never;
    if (!viewer) return deny(req, res, { reason: "unauthorized", statusCode: 401 }, options);
    const scope = await resolveScope(req);
    const role = await auth.permissions.subjectRole(viewer, scope);
    if (role && wanted.includes(role.key)) return next();
    return deny(req, res, { reason: "forbidden", scope, statusCode: 403 }, options);
  };
}

function scopeFromParam(scope: string, paramName = ""): ScopeResolver {
  return function resolveScopeFromParam(req: RequestLike) {
    const params = (req.params && typeof req.params === "object" ? req.params : {}) as Record<string, unknown>;
    return { entityId: paramName ? normalize.toString(params[paramName]) : "", scope };
  };
}

export { normalizeRequirement, requirePermission, requireRole, scopeFromParam };
export type { Denial, GuardOptions, ScopeResolver };
