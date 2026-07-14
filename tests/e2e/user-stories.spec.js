const { test, expect } = require("@playwright/test");

const baseURL = process.env.PAPER_E2E_BASE_URL || "http://127.0.0.1:18081";

test("sender creates a sealed note that cannot be revealed twice", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: baseURL });
  await page.goto(baseURL);

  await expect(page.locator("#create-view")).toBeVisible();
  await expect(page.locator("#reveal-view")).toBeHidden();
  await expect(page.locator("#secret")).toBeFocused();
  await expect(page).toHaveTitle("Paper — seal a one-view note");

  await page.locator("#secret").fill("This payload is too large.");
  await expect(page.locator("#char-count")).toContainText("26 / 20");
  await expect(page.locator("#char-count")).toHaveCSS("color", "rgb(217, 48, 37)");

  await page.locator("#secret").fill("Meet at 9.");
  await expect(page.locator("#char-count")).toContainText("10 / 20");

  await page.locator("button[type='submit']").click();
  await expect(page.locator("#result")).toBeVisible();
  await expect(page.locator("#classification-stamp")).toHaveText("ARMED");
  await expect(page.locator("#secret")).toHaveValue("");

  const shareURL = await page.locator("#share-url").inputValue();
  const parsedShareURL = new URL(shareURL);
  expect(parsedShareURL.origin).toBe(new URL(baseURL).origin);
  expect(parsedShareURL.pathname).toMatch(/^\/s\/[A-Za-z0-9_-]{22}$/);
  expect(parsedShareURL.hash).toMatch(/^#[A-Za-z0-9_-]+$/);

  await page.locator("#copy-link").click();
  await expect(page.locator("#status")).toContainText("Link copied.");
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(shareURL);

  await page.goto(shareURL);
  await expect(page.locator("#create-view")).toBeHidden();
  await expect(page.locator("#reveal-view")).toBeVisible();
  await expect(page.locator("#classification-stamp")).toHaveText("EYES ONLY");
  await expect(page).toHaveTitle("Paper — sealed transmission");

  await page.locator("#reveal-button").click();
  await expect(page.locator("#secret-output")).toHaveText("Meet at 9.");
  await expect(page.locator("#copy-secret")).toBeVisible();
  await expect(page.locator("#reveal-button")).toBeHidden();
  await expect(page.locator("#classification-stamp")).toHaveText("DECLASSIFIED");
  expect(page.url()).not.toContain("#");

  await page.locator("#copy-secret").click();
  await expect(page.locator("#status")).toContainText("Secret copied.");
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe("Meet at 9.");

  const secondPage = await page.context().newPage();
  await secondPage.goto(shareURL);
  await secondPage.locator("#reveal-button").click();
  await expect(secondPage.locator("#status")).toContainText("Could not reveal secret: secret is unavailable or already used");
});

test("recipient sees a clear error when the decryption key fragment is missing", async ({ page }) => {
  await page.goto(`${baseURL}/s/aaaaaaaaaaaaaaaaaaaaaa`);

  await expect(page.locator("#reveal-view")).toBeVisible();
  await expect(page.locator("#reveal-button")).toBeDisabled();
  await expect(page.locator("#status")).toContainText("Missing #decryption-key fragment");
});

test("mobile layout does not create horizontal overflow in primary states", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(baseURL);

  await expect(page.locator("#create-view")).toBeVisible();
  await expect(page.locator(".classified-bar__brand span")).toBeHidden();
  let overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);

  await page.locator("#secret").fill("Mobile payload");
  await page.locator("button[type='submit']").click();
  await expect(page.locator("#result")).toBeVisible();
  overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);

  const shareURL = await page.locator("#share-url").inputValue();
  await page.goto(shareURL);
  await expect(page.locator("#reveal-view")).toBeVisible();
  overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);
});
