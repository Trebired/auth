import type { ResolvedRole, ScopeDefinition } from "#hfap0x87te96";
import { normalizeRoleKey, WILDCARD } from "./keys.js";
import { expandPermissions, resolveRoleAlias } from "./aliases.js";

const WEAKEST = -1;

function roleOrder(definition: ScopeDefinition | null): string[] {
  return definition ? Object.keys(definition.roles || {}).map(normalizeRoleKey).filter(Boolean) : [];
}

function rankStrategy(definition: ScopeDefinition | null) {
  return definition && definition.rank === "privilege" ? "privilege" : "declared";
}

function privilegeScore(permissions: unknown): number {
  const list = Array.isArray(permissions) ? permissions : [];
  if (list.includes(WILDCARD)) return Number.MAX_SAFE_INTEGER;
  return list.length;
}

function declaredRank(definition: ScopeDefinition | null, roleKey: unknown): number {
  const key = resolveRoleAlias(roleKey, definition);
  if (!key) return WEAKEST;
  return roleOrder(definition).indexOf(key);
}

function rankRole(definition: ScopeDefinition | null, roleKey: unknown): number {
  if (rankStrategy(definition) !== "privilege") return declaredRank(definition, roleKey);
  const key = resolveRoleAlias(roleKey, definition);
  const role = key && definition ? (definition.roles || {})[key] : null;
  return role ? privilegeScore(expandPermissions(role.permissions, definition)) : WEAKEST;
}

function rankResolvedRole(definition: ScopeDefinition | null, role: ResolvedRole | null): number {
  if (!role) return WEAKEST;
  if (rankStrategy(definition) !== "privilege") return declaredRank(definition, role.key);
  return privilegeScore(role.permissions);
}

function outranks(definition: ScopeDefinition | null, actorRoleKey: unknown, targetRoleKey: unknown): boolean {
  const actor = rankRole(definition, actorRoleKey);
  if (actor === WEAKEST) return false;
  return actor > rankRole(definition, targetRoleKey);
}

function outranksResolved(
  definition: ScopeDefinition | null,
  actor: ResolvedRole | null,
  target: ResolvedRole | null,
): boolean {
  const actorRank = rankResolvedRole(definition, actor);
  if (actorRank === WEAKEST) return false;
  return actorRank > rankResolvedRole(definition, target);
}

export { outranks, outranksResolved, privilegeScore, rankResolvedRole, rankRole, rankStrategy, roleOrder, WEAKEST };
