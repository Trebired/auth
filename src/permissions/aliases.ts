import type { ScopeDefinition } from "#hfap0x87te96";
import { normalizePermission, normalizeRoleKey } from "./keys.js";

function expandPermissions(permissions: unknown, definition: ScopeDefinition | null): string[] {
  const list = Array.isArray(permissions) ? permissions : [];
  const aliases = definition && definition.aliases && typeof definition.aliases === "object" ? definition.aliases : {};
  const expanded = new Set<string>();
  for (const entry of list) {
    const permission = normalizePermission(entry);
    if (!permission) continue;
    const targets = aliases[permission];
    if (Array.isArray(targets) && targets.length) {
      for (const target of targets) {
        const expandedTarget = normalizePermission(target);
        if (expandedTarget) expanded.add(expandedTarget);
      }
      expanded.add(permission);
      continue;
    }
    expanded.add(permission);
  }
  return [...expanded];
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
  const declared = Array.isArray(definition.declared) ? definition.declared : [];
  if (declared.length) return declared.map(normalizePermission).filter(Boolean);
  const fromRoles = new Set<string>();
  for (const role of Object.values(definition.roles || {})) {
    for (const permission of expandPermissions(role.permissions, definition)) fromRoles.add(permission);
  }
  for (const alias of Object.keys(definition.aliases || {})) fromRoles.add(normalizePermission(alias));
  return [...fromRoles].filter(Boolean);
}

export { declaredPermissions, expandPermissions, resolveRoleAlias };
