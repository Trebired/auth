import assert from "node:assert/strict";

const SECRET = "verify-secret-key";

function subject(id, extra = {}) {
  return { id, ...extra };
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
  verifyExpansion(auth);
  await verifyPrivilegeRank(dist, store);
  await verifyRoleKeyReader(dist);
  await verifyDevices(dist);
}

async function verifyAliasRequirements(auth) {
  const lister = subject("l", { roles: { platform: "lister" } });
  assert.equal(await auth.can(lister, "manage:platform.user", { scope: "platform" }), true, "holding every target answers the alias");
  assert.equal(await auth.can(lister, "manage:platform.everything", { scope: "platform" }), true, "a nested alias expands through");
  const partial = subject("p", { roles: { platform: "creator" } });
  assert.equal(await auth.can(partial, "manage:platform.user", { scope: "platform" }), false, "holding one target is not the alias");
}

async function verifyDevices(dist) {
  const store = dist.createMemoryStore([subject("dev")]);
  const auth = dist.createAuth({ secret: SECRET, store });
  const headers = {
    "sec-ch-ua": '"Brave";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-model": '"Pixel 8"',
    "sec-ch-ua-platform": '"Android"',
    "user-agent": "Mozilla/5.0 (Linux; Android 14) Chrome/131.0.0.0 Mobile Safari/537.36",
  };
  const opened = await auth.startSession(await auth.loadSubject("dev"), { headers });
  const device = opened.session.device;
  assert.equal(device.browserName, "Brave", "a client hint names the browser over the user agent");
  assert.equal(device.model, "Pixel 8", "the device model is kept");
  assert.equal(device.deviceType, "mobile", "the mobile hint sets the device type");
  assert.equal(device.details["sec_ch_ua"].includes("Brave"), true, "the raw hints are kept for the application");
  const given = await auth.startSession(await auth.loadSubject("dev"), { device: { label: "Kiosk", model: "K1" } });
  assert.equal(given.session.device.label, "Kiosk", "a prepared device is taken as given");
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

function verifyExpansion(auth) {
  assert.deepEqual(
    auth.permissions.expand("platform", "manage:platform.user").sort(),
    ["create:platform.user", "delete:platform.user"],
    "expanding a requirement lists what it asks for",
  );
  assert.deepEqual(auth.permissions.expand("platform", "view:platform.user"), ["view:platform.user"], "a plain permission expands to itself");
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

export { verifyDevices, verifyRoleEngine };
