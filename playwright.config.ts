import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./browser",
  testMatch: "*.browser.spec.ts",
  timeout: 60_000,
  workers: 1,
  reporter: "list",
});
