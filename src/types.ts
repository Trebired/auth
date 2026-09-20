type PermissionRequirement = {
  all?: string[];
  any?: string[];
};

type RoleDefinition = {
  label?: string;
  permissions: string[];
};

type ScopeOverride = {
  permission: string;
  scope: string;
};

type ScopeDefinition = {
  overriddenBy?: ScopeOverride[];
  roles: Record<string, RoleDefinition>;
};

type PasswordPolicy = {
  minLength: number;
  requireDigit: boolean;
  requireLowercase: boolean;
  requireSpecial: boolean;
  requireUppercase: boolean;
  rejectWhitespace: boolean;
  saltRounds: number;
};

type SessionPolicy = {
  cookieName: string;
  idleTimeout: string;
  maxPerSubject: number;
  ttl: string;
};

type TwoFactorPolicy = {
  digits: number;
  issuer: string;
  pendingTtl: string;
  secretBytes: number;
  step: number;
  window: number;
};

type CodePolicy = {
  alphabet: string;
  length: number;
  ttl: string;
};

type AuthConfig = {
  codes: { activation: CodePolicy; backup: CodePolicy };
  forVersion?: string;
  password: PasswordPolicy;
  permissions: Record<string, ScopeDefinition>;
  session: SessionPolicy;
  twoFactor: TwoFactorPolicy;
};

type AuthConfigInput = {
  codes?: { activation?: Partial<CodePolicy>; backup?: Partial<CodePolicy> };
  forVersion?: string;
  password?: Partial<PasswordPolicy>;
  permissions?: Record<string, ScopeDefinition>;
  session?: Partial<SessionPolicy>;
  twoFactor?: Partial<TwoFactorPolicy>;
};

type SessionDevice = {
  browserName: string;
  browserVersion: string;
  deviceType: string;
  label: string;
  osName: string;
  userAgent: string;
};

type SessionRecord = {
  createdAt: string;
  device: SessionDevice;
  expiresAt: string;
  id: string;
  ip: string;
  lastSeenAt: string;
  locale: string;
};

type TwoFactorState = {
  disabledAt: string;
  enabled: boolean;
  enabledAt: string;
  pendingExpiresAt: string;
  pendingSecret: string;
  secret: string;
};

type StoredAuthState = {
  activation: { code: string; createdAt: string; expiresAt: string; usedAt: string };
  backupCode: { hash: string; lastUsedAt: string; revealCount: number; secret: string };
  passwordHash: string;
  sessions: SessionRecord[];
  twoFactor: TwoFactorState;
};

type SubjectRoles = Record<string, string|Record<string, string>>;

type AuthSubject = {
  auth?: Partial<StoredAuthState>|null;
  id: string;
  roles?: SubjectRoles | null;
};

type AuthStore = {
  findSubjectByIdentifier?: (identifier: string) => Promise<AuthSubject|null>;
  loadSubject: (id: string) => Promise<AuthSubject|null>;
  saveAuthState: (id: string, state: StoredAuthState) => Promise<boolean>;
};

type PermissionCheckScope = {
  entityId?: string;
  scope: string;
};

export type {
  AuthConfig,
  AuthConfigInput,
  AuthStore,
  AuthSubject,
  CodePolicy,
  PasswordPolicy,
  PermissionCheckScope,
  PermissionRequirement,
  RoleDefinition,
  ScopeDefinition,
  ScopeOverride,
  SessionDevice,
  SessionPolicy,
  SessionRecord,
  StoredAuthState,
  SubjectRoles,
  TwoFactorPolicy,
  TwoFactorState,
};
