# Changelog

All notable changes to `@trebired/auth` will be documented here.

This project follows semantic versioning once published.

## 0.3.0

- Added a per-scope ranking strategy. `rank: "privilege"` ranks a role by how many permissions it holds after alias expansion, with `all` above every list, so roles created at runtime rank against configured ones without a declaration order. `rank: "declared"`, the default, keeps declaration order.
- Changed `rank()` and `outranks()` to be asynchronous and to take an optional entity id, so a role held in storage is ranked like a configured one.
- Fixed an unknown role ranking as the strongest role rather than the weakest.

## 0.2.0

- Added permission aliases. A scope declares `aliases`, where one key stands for a list, so a role holding `manage:platform.user` holds every permission that alias names without the list being copied into the role. The alias itself still answers a check.
- Added `roleAliases`, which map an old or external role key onto a declared one.
- Added a role provider. `createAuth({ roles })` takes a function called with the scope, role key and entity id when the config does not declare that role, so roles created at runtime and kept in the application's storage resolve like configured ones. A resolved role reports whether it came from config or from the provider.
- Added role order: roles are declared weakest first, `rank()` returns that position, `outranks()` compares two roles, and an unknown role ranks last.
- Added permission declaration and validation: `declared(scope)` lists every permission a scope knows, and `validatePermissions(scope, permissions)` splits a list into valid and invalid, which is what a role editor needs before saving.
- Added role reading from a subject that marks its current role (`{ admin: { current: true } }`), alongside the plain `{ scope: "role" }` shape.
- Changed `can()` and `satisfies()` to be asynchronous, because a role can come from storage. `requirePermission` awaits the decision.

## 0.1.0

- Added password credentials: bcrypt hashing at a configurable cost, verification that runs against a dummy hash when the subject or hash is missing so an unknown identifier costs the same as a known one, and a policy check that reports which rules failed instead of a message.
- Added session tokens and login sessions: signed tokens naming a subject and one session, session records with device, address, locale and expiry, last-seen stamping on every authentication, revoking one session or all of them, and trimming to a configured maximum that always keeps the session being opened.
- Added TOTP two-factor following RFC 6238: secret generation, otpauth URLs, constant-time verification with a drift window, and a setup lifecycle where a pending secret expires until it is confirmed with a real code.
- Added backup and activation codes: generation from a configurable alphabet and length, hashed storage, single use, reveal counting, and expiry.
- Added the permission engine: `action:resource` keys, roles that list keys or the single key `all`, per-scope and per-entity role assignments, requirement objects with `all` and `any`, and scope overrides so a platform-wide permission answers for every entity without copying roles.
- Added `.trebired/auth/config.ts` support through `defineConfig` and `loadAuthConfig`, covering the password policy, session policy, two-factor policy, code policies and the permission scopes. Every key has a default.
- Added the Express entry: `attachViewer`, `requireAuth`, `requirePermission`, `setSessionCookie`, `clearSessionCookie`.
- Added `createMemoryStore` so the store interface can be exercised without a database.
