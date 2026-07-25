const { defineConfig } = require("@playwright/test");

const port = process.env.PAPER_E2E_PORT || "18081";
const baseURL = process.env.PAPER_E2E_BASE_URL || `http://127.0.0.1:${port}`;
const originPort = process.env.PAPER_E2E_ORIGIN_PORT || "18082";

module.exports = defineConfig({
  testDir: "tests/e2e",
  use: {
    baseURL,
  },
  projects: [
    {
      name: "default",
      testIgnore: /public-origin\.spec\.js/,
    },
    {
      // Served with PAPER_PUBLIC_ORIGIN set, and reached over a different
      // hostname so share links built from the browser origin stand out.
      name: "public-origin",
      testMatch: /public-origin\.spec\.js/,
      use: { baseURL: `http://localhost:${originPort}` },
    },
  ],
  webServer: [
    {
      command: `rm -f /tmp/paper-e2e.db /tmp/paper-e2e.db-* && PAPER_ADDR=127.0.0.1:${port} PAPER_DB=/tmp/paper-e2e.db PAPER_MAX_SECRET_BYTES=20 go run .`,
      url: baseURL,
      reuseExistingServer: true,
      timeout: 30_000,
    },
    {
      command: `rm -f /tmp/paper-e2e-origin.db /tmp/paper-e2e-origin.db-* && PAPER_ADDR=127.0.0.1:${originPort} PAPER_DB=/tmp/paper-e2e-origin.db PAPER_PUBLIC_ORIGIN=http://127.0.0.1:${originPort} go run .`,
      url: `http://127.0.0.1:${originPort}`,
      reuseExistingServer: true,
      timeout: 30_000,
    },
  ],
});
