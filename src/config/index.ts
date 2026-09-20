import path from "node:path";
import { pathToFileURL } from "node:url";
import { normalizers as normalize } from "@trebired/utils";
import type { AuthConfig, AuthConfigInput, CodePolicy, ScopeDefinition } from "#hfap0x87te96";

const CONFIG_RELATIVE_PATH = ".trebired/auth/config.ts";

const DEFAULT_CONFIG: AuthConfig = {
  codes: {
    activation: { alphabet: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", length: 6, ttl: "7d" },
    backup: { alphabet: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", length: 10, ttl: "" },
  },
  password: {
    minLength: 9,
    rejectWhitespace: true,
    requireDigit: true,
    requireLowercase: true,
    requireSpecial: true,
    requireUppercase: true,
    saltRounds: 10,
  },
  permissions: {},
  session: { cookieName: "token", idleTimeout: "", maxPerSubject: 20, ttl: "7d" },
  twoFactor: { digits: 6, issuer: "", pendingTtl: "10m", secretBytes: 20, step: 30, window: 1 },
};

function defineConfig(config: AuthConfigInput): AuthConfigInput {
  return config;
}

function mergeCodePolicy(base: CodePolicy, input: Partial<CodePolicy>|undefined): CodePolicy {
  const source = input && typeof input === "object" ? input : {};
  return {
    alphabet: normalize.toString(source.alphabet) || base.alphabet,
    length: Math.max(1, Number(source.length) || base.length),
    ttl: source.ttl === undefined ? base.ttl : normalize.toString(source.ttl),
  };
}

function mergeScopes(input: Record<string, ScopeDefinition>|undefined): Record<string, ScopeDefinition> {
  const source = input && typeof input === "object" ? input : {};
  const scopes: Record<string, ScopeDefinition> = {};
  for (const [key, definition] of Object.entries(source)) {
    const scopeKey = normalize.toString(key).trim().toLowerCase();
    if (!scopeKey || !definition || typeof definition !== "object") continue;
    scopes[scopeKey] = {
      overriddenBy: Array.isArray(definition.overriddenBy) ? definition.overriddenBy : [],
      roles: definition.roles && typeof definition.roles === "object" ? definition.roles : {},
    };
  }
  return scopes;
}

function normalizeAuthConfig(input: AuthConfigInput | null | undefined): AuthConfig {
  const source = input && typeof input === "object" ? input : {};
  return {
    codes: {
      activation: mergeCodePolicy(DEFAULT_CONFIG.codes.activation, source.codes?.activation),
      backup: mergeCodePolicy(DEFAULT_CONFIG.codes.backup, source.codes?.backup),
    },
    forVersion: normalize.toString(source.forVersion),
    password: { ...DEFAULT_CONFIG.password, ...(source.password || {}) },
    permissions: mergeScopes(source.permissions),
    session: { ...DEFAULT_CONFIG.session, ...(source.session || {}) },
    twoFactor: { ...DEFAULT_CONFIG.twoFactor, ...(source.twoFactor || {}) },
  };
}

async function loadAuthConfig(rootDir: string = process.cwd()): Promise<AuthConfig> {
  const file = path.resolve(rootDir, CONFIG_RELATIVE_PATH);
  try {
    const loaded = await import(pathToFileURL(file).href);
    const config = loaded && typeof loaded === "object" ? loaded.default ||loaded : null;
    return normalizeAuthConfig(config as AuthConfigInput);
  } catch {
    return normalizeAuthConfig(null);
  }
}

export { CONFIG_RELATIVE_PATH, DEFAULT_CONFIG, defineConfig, loadAuthConfig, normalizeAuthConfig };
