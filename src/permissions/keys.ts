import { normalizers as normalize } from "@trebired/utils";

const PERMISSION_PATTERN = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*:[a-z0-9_]+(?:\.[a-z0-9_]+)*$/u;
const ROLE_KEY_PATTERN = /^[a-z][a-z0-9_-]{1,48}$/u;
const WILDCARD = "all";

function normalizePermission(input: unknown) {
  return normalize.toString(input).trim().toLowerCase();
}

function normalizeRoleKey(input: unknown) {
  return normalize.toString(input).trim().toLowerCase();
}

function isPermissionKey(input: unknown) {
  const permission = normalizePermission(input);
  return permission === WILDCARD || PERMISSION_PATTERN.test(permission);
}

function isRoleKey(input: unknown) {
  return ROLE_KEY_PATTERN.test(normalizeRoleKey(input));
}

function permissionAction(input: unknown) {
  const permission = normalizePermission(input);
  return permission.includes(":") ? permission.slice(0, permission.indexOf(":")) : "";
}

function permissionResource(input: unknown) {
  const permission = normalizePermission(input);
  return permission.includes(":") ? permission.slice(permission.indexOf(":") + 1) : "";
}

export { isPermissionKey, isRoleKey, normalizePermission, normalizeRoleKey, permissionAction, permissionResource, WILDCARD };
