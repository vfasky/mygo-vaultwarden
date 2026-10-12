import { defineConfig } from "cf/config";

export default defineConfig({
  worker: {
    name: "mygo-vaultwarden-web",
    compatibilityDate: "2026-10-01",
    observability: { enabled: true },
    assets: { htmlHandling: "auto-trailing-slash", notFoundHandling: "404-page" },
    domains: ["mygo-vault.vfasky.com"],
  },
});
