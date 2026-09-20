import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolveLogger } from "@package/logger-adapter";

const log = resolveLogger({ source: "@trebired/auth" });
const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const SECRET = "verify-secret-key";

async function importDist(subpath = "index.js") {
  return await import(path.join(rootDir, "dist", subpath));
}

function subject(id, extra = {}) {
  return { email: `${id}@example.test`, id, username: id, ...extra };
}

async function verifyPasswords(auth) {
  const weak = auth.checkPassword("short");
  assert.equal(weak.ok, false, "a weak password fails the policy");
  assert.ok(weak.failed.includes("minLength"), "the failing rules are named");
  assert.equal(auth.checkPassword("Str0ng!Passw0rd").ok, true, "a compliant password passes");
}

async function verifySignIn(auth, store) {
  const person = store.subjects.get("ada");
  await auth.setPassword(person, "Str0ng!Passw0rd");
  const wrong = await auth.signIn("ada", "Wr0ng!Passw0rd", {});
  assert.equal(wrong.reason, "invalid-credentials", "a wrong password is refused");
  const missing = await auth.signIn("nobody", "Str0ng!Passw0rd", {});
  assert.equal(missing.reason, "invalid-credentials", "an unknown identifier is refused");
  const signed = await auth.signIn("ada", "Str0ng!Passw0rd", { headers: { "user-agent": "Mozilla/5.0 Firefox/141.0" } });
  assert.equal(signed.reason, "ok", "the right password signs in");
  assert.ok(signed.token, "a session token is issued");
  assert.equal(signed.session.device.browserName, "Firefox", "the session records its device");
  return signed;
}

async function verifySessions(auth, store, signed) {
  const authenticated = await auth.authenticate(signed.token);
  assert.equal(authenticated.subject.id, "ada", "a token authenticates its subject");
  assert.equal(authenticated.session.id, signed.session.id, "the token names its session");
  assert.equal(await auth.authenticate("not-a-token"), null, "a forged token authenticates nobody");
  const person = store.subjects.get("ada");
  await auth.signOut(person, signed.session.id);
  assert.equal(await auth.authenticate(signed.token), null, "a revoked session stops authenticating");
}

async function verifySessionLimit(dist, store) {
  const limited = dist.createAuth({ config: { session: { maxPerSubject: 3 } }, secret: SECRET, store });
  const newest = [];
  for (let index = 0; index < 5; index += 1) newest.push(await limited.sessions.open(store.subjects.get("ada"), {}));
  const open = await limited.sessions.list(store.subjects.get("ada"));
  assert.equal(open.length, 3, "sessions are trimmed to the configured limit");
  assert.ok(open.some((entry) => entry.id === newest[4].id), "the newest session survives the trim");
}

async function verifyTwoFactor(dist, auth, store) {
  const person = () => store.subjects.get("ada");
  const setup = await auth.twoFactor.begin(person(), "ada@example.test");
  assert.match(setup.otpauthUrl, /^otpauth:\/\/totp\//u, "setup returns an otpauth url");
  assert.equal(await auth.twoFactor.confirm(person(), "000000"), false, "a wrong code does not enable two-factor");
  const code = dist.totp(setup.secret, auth.config.twoFactor);
  assert.equal(await auth.twoFactor.confirm(person(), code), true, "the right code enables two-factor");
  assert.equal(auth.twoFactor.verify(person(), dist.totp(setup.secret, auth.config.twoFactor)), true, "codes verify");
  const signed = await auth.signIn("ada", "Str0ng!Passw0rd", {});
  assert.equal(signed.reason, "two-factor-required", "sign-in stops for the second factor");
  assert.equal(await auth.twoFactor.disable(person()), true, "two-factor can be turned off");
}

async function verifyCodes(auth, store) {
  const person = () => store.subjects.get("ada");
  const backup = await auth.codes.issueBackupCode(person());
  assert.equal(backup.length, auth.config.codes.backup.length, "a backup code uses the configured length");
  const revealed = await auth.codes.revealBackupCode(person());
  assert.equal(revealed.code, backup, "the backup code can be revealed");
  assert.equal(revealed.revealCount, 1, "reveals are counted");
  assert.equal(await auth.codes.redeemBackupCode(person(), "WRONGCODE1"), false, "a wrong backup code is refused");
  assert.equal(await auth.codes.redeemBackupCode(person(), backup), true, "the backup code is redeemed");
  assert.equal(await auth.codes.redeemBackupCode(person(), backup), false, "a redeemed backup code is spent");
  const activation = await auth.codes.issueActivationCode(person());
  assert.equal(await auth.codes.redeemActivationCode(person(), activation.toLowerCase()), true, "activation is case free");
  assert.equal(await auth.codes.redeemActivationCode(person(), activation), false, "an activation code is used once");
}

async function verifyPermissions(auth) {
  const admin = subject("root", { roles: { platform: "admin" } });
  const viewer = subject("vee", { roles: { platform: "viewer" } });
  const owner = subject("owner", { roles: { organization: { org1: "owner" } } });
  assert.equal(await auth.can(admin, "delete:platform.user", { scope: "platform" }), true, "a wildcard role allows anything");
  assert.equal(await auth.can(viewer, "view:platform.user", { scope: "platform" }), true, "a listed permission is allowed");
  assert.equal(await auth.can(viewer, "delete:platform.user", { scope: "platform" }), false, "an unlisted one is refused");
  const inOrg = { entityId: "org1", scope: "organization" };
  assert.equal(await auth.can(owner, "view:organization.member", inOrg), true, "entity roles apply");
  assert.equal(await auth.can(owner, "view:organization.member", { entityId: "org2", scope: "organization" }), false, "roles do not leak");
  assert.equal(await auth.can(admin, "view:organization.member", { entityId: "org2", scope: "organization" }), true, "an override wins");
  assert.equal(await auth.can(null, "view:platform.user", { scope: "platform" }), false, "nobody is never allowed");
  const any = { any: ["view:platform.user", "x:y"] };
  assert.equal(await auth.permissions.satisfies(viewer, any, { scope: "platform" }), true, "any requirements pass");
  const both = { all: ["view:platform.user", "delete:platform.user"] };
  assert.equal(await auth.permissions.satisfies(viewer, both, { scope: "platform" }), false, "all requirements hold the line");
}

async function verifyRoleEngine(dist, store) {
  const auth = dist.createAuth({
      config: {
        permissions: {
          platform: {
            aliases: {
              "manage:platform.everything": ["manage:platform.user"],
              "manage:platform.user": ["create:platform.user", "delete:platform.user"],
            },
            roleAliases: { platform_admin: "admin" },
            roles: {
              viewer: { permissions: ["view:platform.user"] },
              creator: { permissions: ["create:platform.user"] },
              lister: { permissions: ["create:platform.user", "delete:platform.user"] },
              manager: { permissions: ["manage:platform.user"] },
              admin: { permissions: ["all"] },
            },
          },
          organization: { roles: {} },
        },
      },
      roles: (scope, key) => (scope === "organization" && key === "stored_owner" ? { permissions: ["view:organization.member"] } : null),
      secret: SECRET,
      store,
  });
  const manager = subject("m", { roles: { platform: "manager" } });
  assert.equal(await auth.can(manager, "delete:platform.user", { scope: "platform" }), true, "an alias expands to its permissions");
  assert.equal(await auth.can(manager, "manage:platform.user", { scope: "platform" }), true, "the alias itself still answers");
  assert.equal(await auth.can(manager, "view:platform.user", { scope: "platform" }), false, "an alias grants only its own list");
  await verifyAliasRequirements(auth);
  const aliased = subject("a", { roles: { platform: "platform_admin" } });
  assert.equal(await auth.can(aliased, "delete:platform.user", { scope: "platform" }), true, "a role alias resolves to its role");
  const stored = subject("s", { roles: { organization: { org9: "stored_owner" } } });
  const target = { entityId: "org9", scope: "organization" };
  assert.equal(await auth.can(stored, "view:organization.member", target), true, "a provider supplies roles the config does not");
  const resolved = await auth.permissions.resolveRole("organization", "stored_owner", "org9");
  assert.equal(resolved.source, "provider", "a provider role reports where it came from");
  assert.equal(await auth.permissions.outranks("platform", "admin", "viewer"), true, "a later role outranks an earlier one");
  assert.equal(await auth.permissions.outranks("platform", "viewer", "admin"), false, "an earlier role does not outrank a later one");
  assert.equal(await auth.permissions.outranks("platform", "unknown_role", "viewer"), false, "an unknown role outranks nothing");
  assert.equal(await auth.permissions.rank("platform", "manager"), 3, "declared order is the rank");
  const check = auth.permissions.validatePermissions("platform", ["view:platform.user", "invent:platform.thing"]);
  assert.deepEqual(check.invalid, ["invent:platform.thing"], "undeclared permissions are reported");
  assert.equal(check.ok, false, "a role with an undeclared permission is invalid");
  assert.equal(auth.permissions.declared("platform").includes("create:platform.user"), true, "alias targets count as declared");
  await verifyPrivilegeRank(dist, store);
  await verifyRoleKeyReader(dist);
}

async function verifyAliasRequirements(auth) {
  const lister = subject("l", { roles: { platform: "lister" } });
  assert.equal(await auth.can(lister, "manage:platform.user", { scope: "platform" }), true, "holding every target answers the alias");
  assert.equal(await auth.can(lister, "manage:platform.everything", { scope: "platform" }), true, "a nested alias expands through");
  const partial = subject("p", { roles: { platform: "creator" } });
  assert.equal(await auth.can(partial, "manage:platform.user", { scope: "platform" }), false, "holding one target is not the alias");
}

async function verifyRoleKeyReader(dist) {
  const store = dist.createMemoryStore([subject("rk")]);
  const memberships = new Map([["org1", { rk: "owner" }]]);
  const auth = dist.createAuth({
      config: {
        permissions: { organization: { declared: ["view:organization.member"], roles: { owner: { permissions: ["all"] } } } },
      },
      roleKey: (person, scope, entityId) => (memberships.get(entityId) || {})[person && person.id] || "",
      secret: SECRET,
      store,
  });
  const viewer = await auth.loadSubject("rk");
  const target = { entityId: "org1", scope: "organization" };
  assert.equal(await auth.can(viewer, "view:organization.member", target), true, "a role read from elsewhere answers");
  assert.equal(await auth.can(viewer, "view:organization.member", { entityId: "org2", scope: "organization" }), false, "another entity has no role");
}

async function verifyPrivilegeRank(dist, store) {
  const auth = dist.createAuth({
      config: {
        permissions: {
          platform: {
            rank: "privilege",
            roles: {
              admin: { permissions: ["all"] },
              editor: { permissions: ["view:platform.user", "delete:platform.user"] },
              viewer: { permissions: ["view:platform.user"] },
            },
          },
        },
      },
      roles: (scope, key) => (key === "auditor" ? { permissions: ["view:platform.user", "report:platform.user"] } : null),
      secret: SECRET,
      store,
  });
  assert.equal(await auth.permissions.outranks("platform", "editor", "viewer"), true, "more permissions outrank fewer");
  assert.equal(await auth.permissions.outranks("platform", "viewer", "editor"), false, "fewer permissions do not outrank more");
  assert.equal(await auth.permissions.outranks("platform", "admin", "editor"), true, "the wildcard outranks every list");
  assert.equal(await auth.permissions.outranks("platform", "auditor", "viewer"), true, "a provider role is ranked like a configured one");
  assert.equal(await auth.permissions.rank("platform", "unknown_role"), -1, "an unknown role ranks weakest");
}

async function verifyEncryptedSecrets(dist) {
  const store = dist.createMemoryStore([subject("enc")]);
  const auth = dist.createAuth({ encryptionKey: "a-long-encryption-key", secret: SECRET, store });
  const person = await auth.loadSubject("enc");
  const setup = await auth.twoFactor.begin(person, "Example");
  const stored = store.subjects.get("enc");
  assert.equal(stored.auth.twoFactor.pendingSecret === setup.secret, false, "the pending secret is not stored in the clear");
  assert.equal(dist.isEncryptedSecret(stored.auth.twoFactor.pendingSecret), true, "the pending secret is stored encrypted");
  const reloaded = await auth.sessions.list(await auth.loadSubject("enc"));
  assert.equal(Array.isArray(reloaded), true, "a protected store still reads sessions");
  const revealed = auth.readState(store.subjects.get("enc"));
  assert.equal(revealed.twoFactor.pendingSecret, setup.secret, "loading a subject reveals the secret");
  const code = await auth.codes.issueBackupCode(await auth.loadSubject("enc"));
  const afterCode = store.subjects.get("enc");
  assert.equal(dist.isEncryptedSecret(afterCode.auth.backupCode.secret), true, "the backup code is stored encrypted");
  assert.equal(auth.readState(store.subjects.get("enc")).backupCode.secret, code, "the backup code reads back");
  const other = dist.createSecretCipher("a-different-key");
  assert.equal(other.decrypt(afterCode.auth.backupCode.secret), "", "another key cannot read the secret");
}

async function verifyRateLimit(dist) {
  const store = dist.createMemoryStore([subject("rl")]);
  const auth = dist.createAuth({ config: { login: { maxAttempts: 2, window: "1m" } }, secret: SECRET, store });
  await auth.setPassword(await auth.loadSubject("rl"), "Str0ng!Passw0rd");
  const wrong = { ip: "10.0.0.7" };
  assert.equal((await auth.signIn("rl", "nope", wrong)).reason, "invalid-credentials", "a wrong password is refused");
  assert.equal((await auth.signIn("rl", "nope", wrong)).reason, "invalid-credentials", "the second attempt is still refused");
  const blocked = await auth.signIn("rl", "Str0ng!Passw0rd", wrong);
  assert.equal(blocked.reason, "rate-limited", "the attempt after the limit is refused outright");
  assert.equal(blocked.retryAfterMs > 0, true, "a blocked attempt says how long to wait");
  assert.equal((await auth.signIn("rl", "Str0ng!Passw0rd", { ip: "10.0.0.8" })).reason, "ok", "another address is unaffected");
  auth.attempts.clear("10.0.0.7");
  assert.equal((await auth.signIn("rl", "Str0ng!Passw0rd", wrong)).reason, "ok", "clearing the address lets it in");
}

async function verifyAccount(dist) {
  const store = dist.createMemoryStore([subject("acc")]);
  const auth = dist.createAuth({ secret: SECRET, store });
  let person = await auth.loadSubject("acc");
  await auth.setPassword(person, "Str0ng!Passw0rd");
  const signed = await auth.signIn("acc", "Str0ng!Passw0rd", {});
  person = await auth.loadSubject("acc");
  await auth.startSession(person, {});
  person = await auth.loadSubject("acc");
  assert.equal((await auth.changePassword(person, "wrong", "An0ther!Passw0rd")).reason, "invalid-password", "the current password is required");
  assert.equal((await auth.changePassword(person, "Str0ng!Passw0rd", "Str0ng!Passw0rd")).reason, "reused-password", "the same password is refused");
  assert.equal((await auth.changePassword(person, "Str0ng!Passw0rd", "short")).reason, "weak-password", "a weak password is refused");
  const changed = await auth.changePassword(person, "Str0ng!Passw0rd", "An0ther!Passw0rd", {
      keepSessionId: signed.session.id,
      revokeOtherSessions: true,
  });
  assert.equal(changed.ok, true, "the password changes");
  person = await auth.loadSubject("acc");
  assert.deepEqual((await auth.sessions.list(person)).map((entry) => entry.id), [signed.session.id], "the other sessions are revoked");
  assert.equal((await auth.signIn("acc", "An0ther!Passw0rd", {})).reason, "ok", "the new password signs in");
  const code = await auth.codes.issueBackupCode(await auth.loadSubject("acc"));
  person = await auth.loadSubject("acc");
  assert.equal(await auth.revealBackupCode(person, "wrong"), null, "revealing needs the password");
  const revealed = await auth.revealBackupCode(await auth.loadSubject("acc"), "An0ther!Passw0rd");
  assert.equal(revealed.code, code, "the password reveals the backup code");
  assert.equal(revealed.revealCount, 1, "a reveal is counted");
}

async function verifyGuards(dist, express) {
  const store = dist.createMemoryStore([subject("g")]);
  const auth = dist.createAuth({
      config: {
        permissions: {
          organization: {
            declared: ["view:organization.member"],
            roles: { member: { permissions: ["view:organization.member"] }, owner: { permissions: ["all"] } },
          },
        },
      },
      secret: SECRET,
      store,
  });
  const viewer = subject("g", { roles: { organization: { org1: "member" } } });
  const seen = [];
  const res = { status: (code) => { seen.push(code); return { end: () => undefined, json: () => undefined }; } };
  const resolve = express.scopeFromParam("organization", "organizationId");
  const guard = express.requirePermission(auth, ["view:organization.member"], resolve);
  await guard({ params: { organizationId: "org1" }, viewer }, res, () => seen.push(200));
  await guard({ params: { organizationId: "org2" }, viewer }, res, () => seen.push(200));
  assert.deepEqual(seen, [200, 403], "an entity the viewer has no role in is refused");
  const denials = [];
  const unknownGuard = express.requirePermission(auth, "invent:organization.thing", resolve, {
      onDenied: (req, response, denial) => denials.push(denial.reason),
  });
  await unknownGuard({ params: { organizationId: "org1" }, viewer }, res, () => seen.push(200));
  assert.deepEqual(denials, ["unknown-permission"], "an undeclared permission is a server error, not a refusal");
  const roleGuard = express.requireRole(auth, ["owner"], resolve);
  await roleGuard({ params: { organizationId: "org1" }, viewer }, res, () => seen.push(200));
  assert.deepEqual(seen, [200, 403, 403], "a role guard refuses a different role");
  const anyGuard = express.requirePermission(auth, { any: ["view:organization.member", "invent:organization.thing"] }, resolve);
  await anyGuard({ params: { organizationId: "org1" }, viewer }, res, () => seen.push(200));
  assert.deepEqual(seen.at(-1), 500, "an undeclared permission inside any is still reported");
}

async function verifyExpress(dist, express, auth, store) {
  const person = store.subjects.get("ada");
  await auth.setPassword(person, "Str0ng!Passw0rd");
  const signed = await auth.signIn("ada", "Str0ng!Passw0rd", {});
  const req = { headers: { cookie: `${auth.config.session.cookieName}=${signed.token}` } };
  let nexted = false;
  await express.attachViewer(auth)(req, {}, () => { nexted = true; });
  assert.equal(nexted, true, "the middleware continues the chain");
  assert.equal(req.viewer.id, "ada", "the middleware attaches the viewer");
  const codes = [];
  const res = { status: (code) => { codes.push(code); return { end: () => undefined, json: () => undefined }; } };
  express.requireAuth()({}, res, () => codes.push(200));
  assert.deepEqual(codes, [401], "an anonymous request is refused");
  const guard = express.requirePermission(auth, "view:platform.user", () => ({ scope: "platform" }));
  await guard({ viewer: subject("vee", { roles: { platform: "viewer" } }) }, res, () => codes.push(200));
  await guard({ viewer: subject("nope", { roles: {} }) }, res, () => codes.push(200));
  assert.deepEqual(codes, [401, 200, 403], "permission guards answer 403 without the permission");
  assert.equal(dist.sessionCookieOptions(auth.config.session, true).secure, true, "cookies stay secure when asked");
}

async function main() {
  const dist = await importDist();
  const express = await importDist("express/index.js");
  const store = dist.createMemoryStore([subject("ada")]);
  const config = (await import(path.join(rootDir, "examples", "auth-config.ts"))).default;
  const auth = dist.createAuth({ config, secret: SECRET, store });

  await verifyEncryptedSecrets(dist);
  await verifyRateLimit(dist);
  await verifyAccount(dist);
  await verifyGuards(dist, express);
  await verifyPasswords(auth);
  const signed = await verifySignIn(auth, store);
  await verifySessions(auth, store, signed);
  await verifySessionLimit(dist, store);
  await verifyTwoFactor(dist, auth, store);
  await verifyCodes(auth, store);
  await verifyPermissions(auth);
  await verifyRoleEngine(dist, store);
  await verifyExpress(dist, express, auth, store);
  log.info("verify.auth", "Auth verification succeeded.");
}

await main();
