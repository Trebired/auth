import type { ScopeDefinition } from "#hfap0x87te96";
import { normalizePermission, normalizeRoleKey, WILDCARD } from "./keys.js";

function aliasMap(definition: ScopeDefinition | null): Record<string, string[]> {
  return definition && definition.aliases && typeof definition.aliases === "object" ? definition.aliases : {};
}

function expandOne(permission: string, aliases: Record<string, string[]>, into: Set<string>, seen: Set<string>) {
  if (seen.has(permission)) return;
  seen.add(permission);
  const targets = aliases[permission];
  if (!Array.isArray(targets) || !targets.length) {
    into.add(permission);
    return;
  }
  for (const target of targets) {
    const key = normalizePermission(target);
    if (key) expandOne(key, aliases, into, seen);
  }
}

function expandPermissions(permissions: unknown, definition: ScopeDefinition | null): string[] {
  const list = Array.isArray(permissions) ? permissions : [];
  const aliases = aliasMap(definition);
  const expanded = new Set<string>();
  for (const entry of list) {
    const permission = normalizePermission(entry);
    if (!permission) continue;
    expandOne(permission, aliases, expanded, new Set());
    if (aliases[permission]) expanded.add(permission);
  }
  return [...expanded];
}

function requiredPermissions(permission: unknown, definition: ScopeDefinition | null): string[] {
  const key = normalizePermission(permission);
  if (!key) return [];
  const targets = new Set<string>();
  expandOne(key, aliasMap(definition), targets, new Set());
  return targets.size ? [...targets] : [key];
}

function allowsPermission(held: unknown, permission: unknown, definition: ScopeDefinition | null) {
  const list = Array.isArray(held) ? held.map((entry) => normalizePermission(entry)).filter(Boolean) : [];
  const wanted = normalizePermission(permission);
  if (!wanted || !list.length) return false;
  if (list.includes(WILDCARD) || list.includes(wanted)) return true;
  const required = requiredPermissions(wanted, definition);
  return required.length > 1 && required.every((entry) => list.includes(entry));
}

function resolveRoleAlias(roleKey: unknown, definition: ScopeDefinition | null): string {
  const key = normalizeRoleKey(roleKey);
  if (!key || !definition) return key;
  const aliases = definition.roleAliases && typeof definition.roleAliases === "object" ? definition.roleAliases : {};
  const target = normalizeRoleKey(aliases[key]);
  return target || key;
}

function declaredPermissions(definition: ScopeDefinition | null): string[] {
  if (!definition) return [];
  const declared = new Set<string>();
  for (const permission of Array.isArray(definition.declared) ? definition.declared : []) {
    const key = normalizePermission(permission);
    if (key) declared.add(key);
  }
  if (!declared.size) {
    for (const role of Object.values(definition.roles || {})) {
      for (const permission of expandPermissions(role.permissions, definition)) declared.add(permission);
    }
  }
  for (const alias of Object.keys(aliasMap(definition))) {
    const key = normalizePermission(alias);
    if (key) declared.add(key);
  }
  return [...declared];
}

export { allowsPermission, declaredPermissions, expandPermissions, requiredPermissions, resolveRoleAlias };
