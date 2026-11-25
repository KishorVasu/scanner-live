import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Browser, type Page } from "@playwright/test";

/**
 * Main flows against the real API and a seeded database (scripts/e2e_seed.py). Every user signs in once per run:
 * the API refuses to reuse an authenticator code step, so re-authentication uses the next 30-second step.
 */

type Cred = { email: string; password: string; totp: string; id: string };
const creds: Record<string, Cred> = JSON.parse(readFileSync(new URL(".creds.json", import.meta.url), "utf8"));

function totp(secretB32: string, offsetSteps = 0): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secretB32.replace(/=+$/, "")) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000) + offsetSteps));
  const h = createHmac("sha1", key).update(counter).digest();
  const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function signIn(browser: Browser, who: string): Promise<Page> {
  const page = await (await browser.newContext()).newPage();
  const c = creds[who];
  await page.goto("/login");
  await page.getByLabel("Email").fill(c.email);
  await page.getByLabel("Password").fill(c.password);
  await page.getByLabel("Authenticator code").fill(totp(c.totp));
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  return page;
}

async function noSeriousA11yIssues(page: Page) {
  const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
  const serious = result.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(serious.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`)).toEqual([]);
}

test.describe.configure({ mode: "serial" });

test("developer: overview separates not scanned, triage a finding, every page passes axe", async ({ browser }) => {
  const page = await signIn(browser, "developer");
  const unscanned = page.getByRole("row", { name: /E2E Unscanned/ });
  await expect(unscanned.getByText("not scanned")).toBeVisible();
  await expect(page.getByRole("row", { name: /E2E Scanned/ }).getByText("not scanned")).toHaveCount(0);
  await noSeriousA11yIssues(page);

  await page.goto("/findings");
  await page.getByRole("button", { name: "Open E2E fixture finding" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Evidence history")).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Save" })).toBeDisabled();
  await dialog.locator(".p-dropdown").click();
  await page.getByRole("option", { name: "in progress" }).click();
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("row", { name: /E2E fixture finding/ }).getByText("in progress")).toBeVisible();
  await noSeriousA11yIssues(page);

  for (const path of ["/projects", "/intelligence", "/integrity", "/approvals", "/reports", "/settings", "/audit"]) {
    await page.goto(path);
    await expect(page.locator("h1")).toBeVisible();
    await noSeriousA11yIssues(page);
  }
});

test("approvals: the requester cannot approve; another approver can, with a fresh code", async ({ browser }) => {
  const a = await signIn(browser, "approver_a");
  const csrf = (await a.context().cookies()).find((c) => c.name === "sp_csrf")!.value;
  const r = await a.request.post("/api/approvals", {
    headers: { "X-CSRF-Token": csrf },
    data: { action: "run_codeql", scope: { repository_id: "00000000-0000-0000-0000-000000000001" }, reason: "e2e fixture" },
  });
  expect(r.status()).toBe(201);

  await a.goto("/approvals");
  const mine = a.getByRole("row", { name: /run_codeql/ });
  await expect(mine.getByRole("button", { name: "Approve" })).toBeDisabled();

  const b = await signIn(browser, "approver_b");
  await b.goto("/approvals");
  await b.getByRole("row", { name: /run_codeql/ }).getByRole("button", { name: "Approve" }).click();
  await b.getByLabel("Authenticator code").fill(totp(creds.approver_b.totp, 1));
  await b.getByRole("button", { name: "Confirm" }).click();
  await expect(b.getByRole("row", { name: /run_codeql/ }).getByText("approved")).toBeVisible();

  // Reports: approver_a requested the seeded draft, so only someone else may approve it.
  await a.goto("/reports");
  await expect(a.getByRole("row", { name: /E2E draft report/ }).getByRole("button", { name: "Approve" })).toBeDisabled();
  const c = await signIn(browser, "approver_c");
  await c.goto("/reports");
  await c.getByRole("row", { name: /E2E draft report/ }).getByRole("button", { name: "Approve" }).click();
  await c.getByLabel("Authenticator code").fill(totp(creds.approver_c.totp, 1));
  await c.getByRole("button", { name: "Confirm" }).click();
  await expect(c.getByRole("row", { name: /E2E draft report/ }).getByText("approved")).toBeVisible();
  const pdf = await c.request.get(`/api/reports/${await reportId(c)}/pdf`);
  expect(pdf.headers()["content-type"]).toBe("application/pdf");
});

async function reportId(page: Page): Promise<string> {
  const list = await (await page.request.get("/api/reports")).json();
  return list.items.find((i: { title: string }) => i.title === "E2E draft report").id;
}
