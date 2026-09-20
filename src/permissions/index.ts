import { normalizers as normalize } from "@trebired/utils";
import type {
  AuthSubject,
  PermissionCheckScope,
  PermissionRequirement,
  ResolvedRole,
  RoleProvider,
  ScopeDefinition,
} from "#hfap0x87te96";
import { declaredPermissions, expandPermissions, resolveRoleAlias } from "./aliases.js";
import { isPermissionKey, normalizePermission, normalizeRoleKey, WILDCARD } from "./keys.js";
import { outranksResolved, rankResolvedRole, roleOrder } from "./hierarchy.js";
import { readSubjectRoles, roleKeyForScope } from "./subject.js";

type PermissionEngine = ReturnType<typeof createPermissionEngine>;

type EngineOptions = {
  roleProvider?: RoleProvider | null;
};

function scopeName(scope: unknown) {
  return normalize.toString(scope).trim().toLowerCase();
}

async function resolveScopeRole(
  definition: ScopeDefinition | null,
  roleProvider: RoleProvider | null,
  target: { entityId: string; roleKey: unknown; scope: string },
): Promise<ResolvedRole|null> {
  const key = resolveRoleAlias(target.roleKey, definition);
  if (!key) return null;
  const configured = definition && definition.roles ? definition.roles[key] : null;
  const provided = configured || (roleProvider ? await roleProvider(target.scope, key, target.entityId) : null);
  if (!provided) return null;
  return {
    key,
    label: normalize.toString(provided.label) || key,
    permissions: expandPermissions(provided.permissions, definition),
    source: configured ? "config" : "provider",
  };
}

async function meetsRequirement(
  can: (subject: AuthSubject | null | undefined, permission: unknown, target: PermissionCheckScope) => Promise<boolean>,
  subject: AuthSubject | null | undefined,
  requirement: PermissionRequirement,
  target: PermissionCheckScope,
) {
  const all = Array.isArray(requirement && requirement.all) ? requirement.all : [];
  const any = Array.isArray(requirement && requirement.any) ? requirement.any : [];
  if (!all.length && !any.length) return false;
  for (const permission of all) if (!(await can(subject, permission, target))) return false;
  if (!any.length) return true;
  for (const permission of any) if (await can(subject, permission, target)) return true;
  return false;
}

type RoleResolver = (scope: unknown, roleKey: unknown, entityId?: string) => Promise<ResolvedRole|null>;

function createRankQueries(definitionFor: (scope: unknown) => ScopeDefinition | null, resolveRole: RoleResolver) {
  async function rank(scope: unknown, roleKey: unknown, entityId = "") {
    return rankResolvedRole(definitionFor(scope), await resolveRole(scope, roleKey, entityId));
  }

  async function outranks(scope: unknown, actorRoleKey: unknown, targetRoleKey: unknown, entityId = "") {
    const [actor, target] = await Promise.all([
        resolveRole(scope, actorRoleKey, entityId),
        resolveRole(scope, targetRoleKey, entityId),
    ]);
    return outranksResolved(definitionFor(scope), actor, target);
  }

  return { outranks, rank };
}

function createScopeQueries(definitionFor: (scope: unknown) => ScopeDefinition | null) {
  function validatePermissions(scope: unknown, permissions: unknown) {
    const declared = new Set(declaredPermissions(definitionFor(scope)));
    const list = Array.isArray(permissions) ? permissions.map(normalizePermission).filter(Boolean) : [];
    const invalid = list.filter((permission) => !isPermissionKey(permission) || !declared.has(permission));
    return { invalid, ok: invalid.length === 0, valid: list.filter((permission) => !invalid.includes(permission)) };
  }

  return {
    declared: (scope: unknown) => declaredPermissions(definitionFor(scope)),
    isDeclared: (scope: unknown, permission: unknown) =>
    declaredPermissions(definitionFor(scope)).includes(normalizePermission(permission)),
    roleOrder: (scope: unknown) => roleOrder(definitionFor(scope)),
    validatePermissions,
  };
}

type SubjectRoleReader = (
  subject: AuthSubject | null | undefined,
  target: PermissionCheckScope,
) => Promise<ResolvedRole|null>;

function createDecision(definitionFor: (scope: unknown) => ScopeDefinition | null, subjectRole: SubjectRoleReader) {
  async function grants(subject: AuthSubject | null | undefined, permission: string, target: PermissionCheckScope) {
    const role = await subjectRole(subject, target);
    if (!role) return false;
    return role.permissions.includes(WILDCARD) || role.permissions.includes(permission);
  }

  return async function can(
    subject: AuthSubject | null | undefined,
    permissionInput: unknown,
    target: PermissionCheckScope,
  ): Promise<boolean> {
    const permission = normalizePermission(permissionInput);
    if (!subject || !isPermissionKey(permission)) return false;
    if (await grants(subject, permission, target)) return true;
    const overrides = definitionFor(target && target.scope)?.overriddenBy || [];
    for (const override of overrides) {
      if (await grants(subject, normalizePermission(override.permission), { scope: override.scope })) return true;
    }
    return false;
  };
}

function createPermissionEngine(scopes: Record<string, ScopeDefinition>, options: EngineOptions = {}) {
  const roleProvider = typeof options.roleProvider === "function" ? options.roleProvider : null;

  function definitionFor(scope: unknown): ScopeDefinition | null {
    const key = scopeName(scope);
    return key && scopes[key] ? scopes[key] : null;
  }

  async function resolveRole(scope: unknown, roleKeyInput: unknown, entityId = "") {
    return await resolveScopeRole(definitionFor(scope), roleProvider, {
        entityId: normalize.toString(entityId),
        roleKey: roleKeyInput,
        scope: scopeName(scope),
    });
  }

  async function subjectRole(subject: AuthSubject | null | undefined, target: PermissionCheckScope) {
    const entityId = normalize.toString(target && target.entityId);
    const roleKey = roleKeyForScope(subject, scopeName(target && target.scope), entityId);
    return roleKey ? await resolveRole(target && target.scope, roleKey, entityId) : null;
  }

  const can = createDecision(definitionFor, subjectRole);

  return {
    ...createScopeQueries(definitionFor),
    ...createRankQueries(definitionFor, resolveRole),
    can,
    resolveRole,
    roleKeyForScope,
    satisfies: (
      subject: AuthSubject | null | undefined,
      requirement: PermissionRequirement,
      target: PermissionCheckScope,
    ) => meetsRequirement(can, subject, requirement, target),
    subjectRole,
  };
}

export { createPermissionEngine, normalizeRoleKey, readSubjectRoles, roleKeyForScope };
export *from "./aliases.js";
export *from "./hierarchy.js";
export *from "./keys.js";
export type { EngineOptions, PermissionEngine };
