import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render(path = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(
    new Request(`http://localhost${path}`, { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the CYPHERYN landing page", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  const html = await response.text();
  assert.match(html, /<title>CYPHERYN — See the Exposure\. Prove the Risk\.<\/title>/i);
  assert.match(html, /Follow every signal/);
  assert.match(html, /Prove every finding/);
  assert.match(html, /href="\/investigations\/new"/);
  assert.match(html, /\/_next\/image\?url=%2Fcypheryn-logo\.png(?:&|&amp;)w=/);
  assert.doesNotMatch(html, /Your site is taking shape|Building your site/);
});

test("keeps security guidance and cross-platform scripts in source", async () => {
  const [help, page, layout, packageJson, providerSettings] = await Promise.all([
    readFile(new URL("../app/_components/FindingHelp.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../app/settings/page.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(help, /How this could be attacked/i);
  assert.match(help, /How to fix it/i);
  assert.match(help, /role="tooltip"/);
  assert.match(page, /Start an investigation/);
  assert.match(layout, /CYPHERYN/);
  assert.match(packageJson, /cross-env WRANGLER_LOG_PATH/);
  assert.doesNotMatch(packageJson, /@rolldown\/binding-darwin-x64/);
  assert.match(providerSettings, /Live verified/);
  assert.match(providerSettings, /last_verified_at/);
  assert.match(providerSettings, /Select an organization/);
  assert.match(providerSettings, /organization\.id\.slice\(0, 8\)/);
  assert.match(providerSettings, /New jobs will use this key/);
});

test("public legal pages render without application state", async () => {
  for (const [path, expected] of [
    ["/terms", /CYPHERYN Terms of Service/],
    ["/responsible-use", /CYPHERYN Responsible Use Policy/],
    ["/privacy", /CYPHERYN Privacy Policy/],
    ["/security", /Responsible Disclosure/],
  ]) {
    const response = await render(path);
    assert.equal(response.status, 200, path);
    const html = await response.text();
    assert.match(html, expected);
    assert.doesNotMatch(html, /REQUIRES REVIEW BY QUALIFIED COUNSEL/);
    assert.match(html, /href="\/terms"/);
    assert.match(html, /href="\/responsible-use"/);
    assert.match(html, /href="\/privacy"/);
  }
});

test("legal acceptance is affirmative and versioned", async () => {
  const response = await render("/legal-acceptance");
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /Review responsible-use terms/);
  assert.match(html, /type="checkbox"/);
  assert.match(html, /Terms of Service/);
  assert.match(html, /Responsible Use Policy/);
});
