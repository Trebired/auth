import { normalizers as normalize } from "@trebired/utils";
import type { AuthSubject, SubjectRoles } from "#hfap0x87te96";
import { normalizeRoleKey } from "./keys.js";

function readSubjectRoles(subject: AuthSubject | null | undefined): SubjectRoles {
  const roles = subject && subject.roles && typeof subject.roles === "object" ? subject.roles : {};
  return roles as SubjectRoles;
}

function currentRoleKey(entry: unknown) {
  if (!entry || typeof entry !== "object") return "";
  for (const [key, value] of Object.entries(entry as Record<string, unknown>)) {
    const record = value && typeof value === "object" ? (value as Record<string, unknown>) : null;
    if (record && record.current === true) return normalizeRoleKey(key);
  }
  return "";
}

function readRoleKey(entry: unknown): string {
  if (typeof entry === "string") return normalizeRoleKey(entry);
  if (!entry || typeof entry !== "object") return "";
  const source = entry as Record<string, unknown>;
  const marked = currentRoleKey(source.role);
  if (marked) return marked;
  const named = normalizeRoleKey(
    source.role_key || source.roleKey || source.current_role_key || source.currentRoleKey || source.key,
  );
  if (named) return named;
  const nested = Object.prototype.hasOwnProperty.call(source, "role") ? source.role : null;
  if (typeof nested === "string") return normalizeRoleKey(nested);
  if (nested && typeof nested === "object") return readRoleKey(nested);
  const keys = Object.keys(source).map(normalizeRoleKey).filter(Boolean);
  return keys.length === 1 ? keys[0] : "";
}

function roleKeyForScope(subject: AuthSubject | null | undefined, scope: string, entityId: string) {
  const assigned = readSubjectRoles(subject)[scope];
  if (typeof assigned === "string") return normalizeRoleKey(assigned);
  if (!assigned || typeof assigned !== "object") return "";
  const map = assigned as Record<string, unknown>;
  if (entityId) {
    const direct = map[entityId];
    if (typeof direct === "string") return normalizeRoleKey(direct);
    if (direct && typeof direct === "object") return currentRoleKey({[normalize.toString((direct as any).key)]: direct });
    return "";
  }
  const marked = currentRoleKey(map);
  if (marked) return marked;
  const values = Object.values(map);
  return values.length === 1 && typeof values[0] === "string" ? normalizeRoleKey(values[0]) : "";
}

export { currentRoleKey, readRoleKey, readSubjectRoles, roleKeyForScope };
