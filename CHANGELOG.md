# Changelog

All notable changes to `@trebired/auth` will be documented here.

This project follows semantic versioning once published.

## 0.1.0

- Added password credentials: bcrypt hashing at a configurable cost, verification that runs against a dummy hash when the subject or hash is missing so an unknown identifier costs the same as a known one, and a policy check that reports which rules failed instead of a message.
- Added session tokens and login sessions: signed tokens naming a subject and one session, session records with device, address, locale and expiry, last-seen stamping on every authentication, revoking one session or all of them, and trimming to a configured maximum that always keeps the session being opened.
- Added TOTP two-factor following RFC 6238: secret generation, otpauth URLs, constant-time verification with a drift window, and a setup lifecycle where a pending secret expires until it is confirmed with a real code.
- Added backup and activation codes: generation from a configurable alphabet and length, hashed storage, single use, reveal counting, and expiry.
- Added the permission engine: `action:resource` keys, roles that list keys or the single key `all`, per-scope and per-entity role assignments, requirement objects with `all` and `any`, and scope overrides so a platform-wide permission answers for every entity without copying roles.
- Added `.trebired/auth/config.ts` support through `defineConfig` and `loadAuthConfig`, covering the password policy, session policy, two-factor policy, code policies and the permission scopes. Every key has a default.
- Added the Express entry: `attachViewer`, `requireAuth`, `requirePermission`, `setSessionCookie`, `clearSessionCookie`.
- Added `createMemoryStore` so the store interface can be exercised without a database.
