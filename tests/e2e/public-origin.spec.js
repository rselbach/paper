const { test, expect } = require("@playwright/test");

const port = process.env.PAPER_E2E_ORIGIN_PORT || "18082";
// The page is served over a hostname that differs from the configured public
// origin, so a share link built from the browser's own origin is visible.
const browserOrigin = `http://localhost:${port}`;
const publicOrigin = `http://127.0.0.1:${port}`;

test("share links use the configured public origin, not the browser's", async ({ page }) => {
  await page.goto(browserOrigin);

  await page.locator("#secret").fill("Six seasons.");
  await page.locator("button[type='submit']").click();
  await expect(page.locator("#result")).toBeVisible();

  const shareURL = await page.locator("#share-url").inputValue();
  const parsedShareURL = new URL(shareURL);
  expect(await page.evaluate(() => window.location.origin)).toBe(browserOrigin);
  expect(parsedShareURL.origin).toBe(publicOrigin);
  expect(parsedShareURL.pathname).toMatch(/^\/s\/[A-Za-z0-9_-]{22}$/);
  expect(parsedShareURL.hash).toMatch(/^#[A-Za-z0-9_-]+$/);
});
