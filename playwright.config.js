const { defineConfig } = require("@playwright/test");

const port = process.env.PAPER_E2E_PORT || "18081";
const baseURL = process.env.PAPER_E2E_BASE_URL || `http://127.0.0.1:${port}`;

module.exports = defineConfig({
  testDir: "tests/e2e",
  use: {
    baseURL,
  },
  webServer: {
    command: `rm -f /tmp/paper-e2e.db /tmp/paper-e2e.db-* && PAPER_ADDR=127.0.0.1:${port} PAPER_DB=/tmp/paper-e2e.db PAPER_MAX_SECRET_BYTES=20 go run .`,
    url: baseURL,
    reuseExistingServer: true,
    timeout: 30_000,
  },
});
