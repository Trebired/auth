# @trebired/auth

Server-side authentication and role-based permissions for Bun applications: password credentials, signed session tokens and cookies, per-subject login sessions with device records, TOTP two-factor, backup and activation codes, and a permission engine declared in `.trebired/auth/config.ts`.

The package owns credential hashing and verification, token signing, session records and their limits, two-factor and code lifecycles, and every permission decision. The caller owns persistence, its user records, its routes, its interface text, and its secret. The package deliberately does not own a database, a user table, a login page, session cookies it was not asked to set, email or SMS delivery, rate limiting, or product role names: roles and permission keys are configuration.

## Install

Runtime support: Bun 1+.

```sh
bun i @trebired/auth
```

## Quick Start

```ts
import { createAuth } from "@trebired/auth";
import { loadAuthConfig } from "@trebired/auth/config";
import { attachViewer, requirePermission, setSessionCookie } from "@trebired/auth/express";

const auth = createAuth({
  config: await loadAuthConfig(),
  secret: process.env.AUTH_SECRET,
  store: {
    findSubjectByIdentifier: (identifier) => users.findByLogin(identifier),
    loadSubject: (id) => users.findById(id),
    saveAuthState: (id, state) => users.saveAuth(id, state),
  },
});

app.use(attachViewer(auth));
app.get("/users", requirePermission(auth, "view:platform.user", () => ({ scope: "platform" })), listUsers);

app.post("/login", async (req, res) => {
  const result = await auth.signIn(req.body.identifier, req.body.password, {
    headers: req.headers,
    ip: req.ip,
  });
  if (result.reason !== "ok") return res.status(401).json({ status_code: result.reason });
  setSessionCookie(auth, res, result.token, req.secure);
  res.json({ ok: true });
});
```

## Concepts

### Subjects and the store

A subject is whatever the application calls a user: `{ id, roles, auth }`. The application supplies a store with `loadSubject`, `saveAuthState` and, for sign-in, `findSubjectByIdentifier`. The package reads and writes one object, the auth state, and never touches the rest of the record. `createMemoryStore()` implements the same interface for verification and local work.

### Auth state

The auth state holds `passwordHash`, `sessions`, `twoFactor`, `backupCode` and `activation`. `readAuthState(subject)` normalizes it, so a partially written record still reads as a complete state.

### Sessions

Signing in opens a session record with its own id, device description, address, locale and expiry, and signs a token naming the subject and that session. Authenticating a token loads the subject, refuses expired or revoked sessions, and stamps the session's last-seen time. Sessions above `session.maxPerSubject` are trimmed oldest first, and the session being opened is always kept.

### Permissions

A permission key is `action:resource`, such as `view:platform.user`. A role lists permission keys, or the single key `all`. A subject carries role assignments per scope: `{ platform: "admin", organization: { "<id>": "owner" } }`. `can(subject, permission, { scope, entityId })` resolves the role for that scope and entity and answers. It is asynchronous, because roles can come from storage. A scope may declare `overriddenBy`, so a platform-wide permission can answer for every organization without copying roles.

### Aliases, order and validation

A scope may declare `aliases`, where one key stands for a list. Expansion runs both ways: a role holding `manage:platform.user` holds every permission that alias names, and a check for `manage:platform.user` passes for a role that holds all of them without naming the alias. Aliases may name other aliases, and a cycle stops at the key that started it. `roleAliases` maps an old or external role key onto a declared one.

Roles are ordered one of two ways, chosen per scope with `rank`. Under `"declared"`, the default, they are declared weakest first and a role's rank is its position. Under `"privilege"`, a role's rank is how many permissions it holds after alias expansion, with `all` above every list; that is what a product needs when roles are created at runtime and have no place in a declaration order. `rank(scope, roleKey, entityId?)` returns the rank and `outranks(scope, actor, target, entityId?)` compares two roles. Both are asynchronous, because either role can come from storage, and an unknown role ranks weakest, so it outranks nothing.

`declared(scope)` lists every permission the scope knows: the `declared` list when given, the roles' permissions otherwise, and the alias keys in both cases. `validatePermissions(scope, permissions)` splits a list into `valid` and `invalid`, which is what a role editor needs before saving.

### Where a role assignment lives

By default a subject carries its own roles. When the assignment lives somewhere else, such as a membership row on the organization, pass `roleKey`: it is called with the subject, the scope and the entity id, and returns the role key for that pair. It may be asynchronous, so it can read the application's tables.

### Roles from storage

Roles that are created at runtime never fit in a config file. `createAuth({ roles })` takes a provider, called with the scope, role key and entity id when the config does not declare that role. A resolved role reports `source: "config"` or `source: "provider"`. Provider roles run through the same alias expansion, so storage holds the same keys an editor shows, and they are ranked like configured ones.

### Sign-in attempts

Failed sign-ins are counted per address, or per identifier when the caller passes no address, inside a rolling window set by `login: { maxAttempts, window }`. An attempt made while blocked returns `reason: "rate-limited"` with `retryAfterMs` and never reaches the store, and a successful sign-in clears the count. `auth.attempts` exposes `read`, `fail`, `clear` and `reset`, so an application can count its own events against the same limiter or clear a block from an admin screen.

### Account changes

`changePassword(subject, current, next, { revokeOtherSessions, keepSessionId })` verifies the current password, refuses the same password again, checks the new one against the policy, and writes the hash and the session list in one save. It answers `invalid-password`, `reused-password`, `weak-password` or `ok`, with the failed policy rules when it is the password that is weak.

`revealBackupCode(subject, password)` verifies the password before it hands the code back, and counts the reveal. `codes.revealBackupCode(subject)` is the ungated form for a caller that has already checked.

### Secrets at rest

The two-factor secret, the pending secret and the backup code are credentials, so they can be encrypted before they reach the store. `createAuth({ encryptionKey })` wraps the store: writes encrypt those three fields, reads decrypt them, and the rest of the record is passed through untouched. `createAuth({ cipher })` takes a cipher of your own instead, which is how an application keeps reading secrets written by an older scheme.

The cipher is AES-256-GCM with a key derived from the given key by scrypt, and a value reads as `v1:<iv>:<tag>:<ciphertext>`. Decryption that fails, including a value written under a different key, yields an empty secret rather than an error. `isEncryptedSecret(value)` reports whether a value was written by this cipher.

Subjects loaded through `auth.loadSubject(id)` and states read through `auth.readState(subject)` come back decrypted. A subject the application loaded by itself still holds the encrypted fields, so read it through one of those two before handing it to a manager.

## Configuration

`.trebired/auth/config.ts`, read by `loadAuthConfig()`:

```ts
import { defineConfig } from "@trebired/auth/config";

export default defineConfig({
  forVersion: "0.1.0",
  password: { minLength: 9, requireSpecial: true },
  login: { maxAttempts: 10, window: "10m" },
  session: { cookieName: "token", maxPerSubject: 20, ttl: "7d" },
  twoFactor: { issuer: "Example", step: 30, window: 1 },
  codes: { activation: { length: 6, ttl: "7d" }, backup: { length: 10 } },
  permissions: {
    platform: {
      roles: {
        admin: { permissions: ["all"] },
        viewer: { permissions: ["view:platform.user"] },
      },
    },
    organization: {
      overriddenBy: [{ permission: "manage:platform.organization", scope: "platform" }],
      roles: {
        owner: { permissions: ["all"] },
        member: { permissions: ["view:organization.member"] },
      },
    },
  },
});
```

Every key has a default, so a config states only what it changes. Durations are `7d`, `12h`, `30m`, `45s` or a plain number of seconds.

## Runtime

The signing secret is passed to `createAuth`, never read from the environment by the package. Rotating it invalidates every issued token.

Password hashing is bcrypt at the configured cost. Verification runs against a dummy hash when a subject or hash is missing, so an unknown identifier costs the same as a known one.

TOTP follows RFC 6238 with SHA-1, the configured digit count and step, and a drift window on each side. Codes are compared in constant time.

## Public API

### Root

`createAuth`, `createAttemptLimiter`, `createMemoryStore`, `createProtectedStore`, `createSecretCipher`, `isEncryptedSecret`, `protectState`, `revealState`, `checkPassword`, `hashPassword`, `verifyPassword`, `createPermissionEngine`, `readAuthState`, `isSessionExpired`, `signSessionToken`, `verifySessionToken`, `sessionCookieOptions`, `durationToMs`, `generateSecret`, `totp`, `verifyTotp`, `otpauthUrl`, and the permission key helpers.

An `Auth` instance exposes `signIn`, `startSession`, `authenticate`, `signOut`, `setPassword`, `changePassword`, `revealBackupCode`, `checkPassword`, `can`, `loadSubject`, `readState`, `attempts`, `cookieOptions`, `config`, and the `sessions`, `twoFactor`, `codes` and `permissions` managers.

### Config

`defineConfig`, `loadAuthConfig`, `normalizeAuthConfig`, `DEFAULT_CONFIG`.

### Express

`attachViewer`, `requireAuth`, `requirePermission`, `requireRole`, `scopeFromParam`, `normalizeRequirement`, `setSessionCookie`, `clearSessionCookie`, `readCookie`.

`requirePermission` takes a permission, a list, or `{ all }` / `{ any }`, and a resolver that reads the scope and entity from the request; `scopeFromParam("organization", "organizationId")` is the usual one. A permission the scope never declared is a fault in the route, not a refusal by the viewer, so it answers 500 and names the permissions. `requireRole` admits only the listed roles for the resolved scope. Both take `onDenied`, which receives the request, the response and a denial naming the reason, the requirement and the scope, so the application shapes its own response and message.

## What It Does Not Do

- No storage. It never opens a database, defines a user table, or writes files.
- No routes, pages, forms, or interface text. It answers; the application responds.
- No email, SMS, or push delivery. It issues codes and verifies them.
- No audit log, and no rate limiting beyond sign-in attempts held in this process. A fleet of processes needs shared storage the application owns.
- No OAuth, SAML, LDAP, or passkeys.
- No role names or permission keys of its own. Both are configuration.
- No secret management. The application supplies the signing and encryption keys and rotates them.
