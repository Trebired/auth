import { defineConfig } from "#tat8s4sbqe1s";

export default defineConfig({
    forVersion: "0.11.0",
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
          member: { permissions: ["view:organization.member"] },
          owner: { permissions: ["all"] },
        },
      },
    },
    session: { cookieName: "token", ttl: "7d" },
    twoFactor: { issuer: "Trebired" },
});
