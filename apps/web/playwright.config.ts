import { defineConfig, devices } from "@playwright/test";

// CI starts the API (seeded by scripts/e2e_seed.py) and `next dev` before running this; see .github/workflows/ci.yml.
export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  timeout: 60_000,
  use: { baseURL: process.env.E2E_BASE_URL ?? "http://127.0.0.1:3000", trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
