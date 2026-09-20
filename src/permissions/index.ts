import { normalizers as normalize } from "@trebired/utils";
import type {
  AuthSubject,
  PermissionCheckScope,
  PermissionRequirement,
  ScopeDefinition,
  SubjectRoles,
} from "#hfap0x87te96";
import { isPermissionKey, normalizePermission, normalizeRoleKey, WILDCARD } from "./keys.js";

type PermissionEngine = ReturnType<typeof createPermissionEngine>;

function readSubjectRoles(subject: AuthSubject | null | undefined): SubjectRoles {
  const roles = subject && subject.roles && typeof subject.roles === "object" ? subject.roles : {};
  return roles as SubjectRoles;
}

function roleKeyForScope(subject: AuthSubject | null | undefined, scope: string, entityId: string) {
  const assigned = readSubjectRoles(subject)[scope];
  if (typeof assigned === "string") return normalizeRoleKey(assigned);
  if (!assigned || typeof assigned !== "object") return "";
  if (entityId) return normalizeRoleKey(assigned[entityId]);
  const values = Object.values(assigned);
  return values.length === 1 ? normalizeRoleKey(values[0]) : "";
}

function meetsRequirement(
  can: (subject: AuthSubject | null | undefined, permission: unknown, target: PermissionCheckScope) => boolean,
  subject: AuthSubject | null | undefined,
  requirement: PermissionRequirement,
  target: PermissionCheckScope,
) {
  const all = Array.isArray(requirement && requirement.all) ? requirement.all : [];
  const any = Array.isArray(requirement && requirement.any) ? requirement.any : [];
  if (!all.length && !any.length) return false;
  if (all.length && !all.every((permission) => can(subject, permission, target))) return false;
  return !any.length || any.some((permission) => can(subject, permission, target));
}

function scopeDeclares(definition: ScopeDefinition | null, permissionInput: unknown) {
  if (!definition) return false;
  const permission = normalizePermission(permissionInput);
  return Object.values(definition.roles || {}).some((role) =>
    Array.isArray(role.permissions) && role.permissions.map(normalizePermission).includes(permission),
  );
}

function createPermissionEngine(scopes: Record<string, ScopeDefinition>) {
  function scopeDefinition(scope: unknown): ScopeDefinition | null {
    const key = normalize.toString(scope).trim().toLowerCase();
    return key && scopes[key] ? scopes[key] : null;
  }

  function permissionsForRole(scope: string, roleKey: string) {
    const definition = scopeDefinition(scope);
    const role = definition && definition.roles ? definition.roles[roleKey] : null;
    if (!role || !Array.isArray(role.permissions)) return [] as string[];
    return role.permissions.map(normalizePermission).filter(Boolean);
  }

  function subjectPermissions(subject: AuthSubject | null | undefined, target: PermissionCheckScope) {
    const scope = normalize.toString(target && target.scope).trim().toLowerCase();
    const entityId = normalize.toString(target && target.entityId);
    const roleKey = roleKeyForScope(subject, scope, entityId);
    return roleKey ? permissionsForRole(scope, roleKey) : ([] as string[]);
  }

  function grantedDirectly(subject: AuthSubject | null | undefined, permission: string, target: PermissionCheckScope) {
    const granted = subjectPermissions(subject, target);
    return granted.includes(WILDCARD) || granted.includes(permission);
  }

  function can(subject: AuthSubject | null | undefined, permissionInput: unknown, target: PermissionCheckScope): boolean {
    const permission = normalizePermission(permissionInput);
    if (!subject || !isPermissionKey(permission)) return false;
    if (grantedDirectly(subject, permission, target)) return true;
    const definition = scopeDefinition(target && target.scope);
    const overrides = definition && Array.isArray(definition.overriddenBy) ? definition.overriddenBy : [];
    return overrides.some((override) =>
      grantedDirectly(subject, normalizePermission(override.permission), { scope: override.scope }),
    );
  }

  return {
    can,
    isDeclared: (scope: unknown, permission: unknown) => scopeDeclares(scopeDefinition(scope), permission),
    permissionsForRole,
    roleKeyForScope,
    satisfies: (subject: AuthSubject | null | undefined, requirement: PermissionRequirement, target: PermissionCheckScope) =>
    meetsRequirement(can, subject, requirement, target),
    subjectPermissions,
  };
}

export { createPermissionEngine, readSubjectRoles, roleKeyForScope };
export *from "./keys.js";
export type { PermissionEngine };
