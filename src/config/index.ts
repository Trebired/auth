import path from "node:path";
import { pathToFileURL } from "node:url";
import { assertCompatibleForVersion, normalizers as normalize } from "@trebired/utils";
import { authLog } from "#lavracp1xbi8";
import { PACKAGE_NAME, PACKAGE_VERSION } from "#4n2n9id6j15b";
import type { AuthConfig, AuthConfigInput, CodePolicy, ScopeDefinition } from "#hfap0x87te96";

const CONFIG_RELATIVE_PATH = ".trebired/auth/config.ts";

const DEFAULT_CONFIG: AuthConfig = {
  codes: {
    activation: { alphabet: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", length: 6, ttl: "7d" },
    backup: { alphabet: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", length: 10, ttl: "" },
  },
  login: { maxAttempts: 10, window: "10m" },
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

function isVersionFailure(error: unknown) {
  const text = typeof error === "string" ? error : normalize.toString(error && (error as Error).message);
  return text.includes("[FAIL, config.version]") || text.includes(PACKAGE_NAME);
}

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
      aliases: definition.aliases && typeof definition.aliases === "object" ? definition.aliases : {},
      declared: Array.isArray(definition.declared) ? definition.declared : [],
      overriddenBy: Array.isArray(definition.overriddenBy) ? definition.overriddenBy : [],
      rank: definition.rank === "privilege" ? "privilege" : "declared",
      roleAliases: definition.roleAliases && typeof definition.roleAliases === "object" ? definition.roleAliases : {},
      roles: definition.roles && typeof definition.roles === "object" ? definition.roles : {},
    };
  }
  return scopes;
}

function checkForVersion(source: AuthConfigInput, configPath = "") {
  return assertCompatibleForVersion({
      compatibility: "major-minor",
      config: source,
      configPath,
      forVersion: source.forVersion,
      label: PACKAGE_NAME,
      packageName: PACKAGE_NAME,
      packageVersion: PACKAGE_VERSION,
      requireForVersion: Boolean(configPath),
  });
}

function normalizeAuthConfig(input: AuthConfigInput | null | undefined, configPath = ""): AuthConfig {
  const source = input && typeof input === "object" ? input : {};
  checkForVersion(source, configPath);
  return {
    codes: {
      activation: mergeCodePolicy(DEFAULT_CONFIG.codes.activation, source.codes?.activation),
      backup: mergeCodePolicy(DEFAULT_CONFIG.codes.backup, source.codes?.backup),
    },
    forVersion: normalize.toString(source.forVersion),
    login: { ...DEFAULT_CONFIG.login, ...(source.login || {}) },
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
    return normalizeAuthConfig(config as AuthConfigInput, file);
  } catch (error) {
    if (isVersionFailure(error)) throw error;
    authLog().warn("config", "auth config was not read, using defaults", { file });
    return normalizeAuthConfig(null);
  }
}

export { CONFIG_RELATIVE_PATH, DEFAULT_CONFIG, defineConfig, loadAuthConfig, normalizeAuthConfig };
