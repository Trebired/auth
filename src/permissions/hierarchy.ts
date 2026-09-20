import type { ScopeDefinition } from "#hfap0x87te96";
import { normalizeRoleKey } from "./keys.js";
import { resolveRoleAlias } from "./aliases.js";

function roleOrder(definition: ScopeDefinition | null): string[] {
  return definition ? Object.keys(definition.roles || {}).map(normalizeRoleKey).filter(Boolean) : [];
}

function rankRole(definition: ScopeDefinition | null, roleKey: unknown): number {
  const key = resolveRoleAlias(roleKey, definition);
  if (!key) return Number.MAX_SAFE_INTEGER;
  const index = roleOrder(definition).indexOf(key);
  return index >= 0 ? index : Number.MAX_SAFE_INTEGER;
}

function outranks(definition: ScopeDefinition | null, actorRoleKey: unknown, targetRoleKey: unknown): boolean {
  const actor = rankRole(definition, actorRoleKey);
  const target = rankRole(definition, targetRoleKey);
  if (actor === Number.MAX_SAFE_INTEGER) return false;
  return actor > target;
}

export { outranks, rankRole, roleOrder };
