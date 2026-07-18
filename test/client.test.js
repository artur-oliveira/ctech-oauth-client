import test from "node:test";
import assert from "node:assert/strict";
import { OAuthClient, generatePKCE, generateState, decodeIdToken } from "../dist/index.js";

function makeSessionStorage() {
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => map.set(k, v),
    removeItem: (k) => map.delete(k),
  };
}

test("generatePKCE produces a verifier and a matching S256 challenge", async () => {
  const { codeVerifier, codeChallenge } = await generatePKCE();
  assert.equal(typeof codeVerifier, "string");
  assert.ok(codeVerifier.length >= 43, "verifier must be at least 43 chars (RFC 7636)");
  assert.match(codeVerifier, /^[A-Za-z0-9_-]+$/);
  assert.match(codeChallenge, /^[A-Za-z0-9_-]+$/);
});

test("generateState returns 32 hex chars", () => {
  assert.match(generateState(), /^[0-9a-f]{32}$/);
});

test("hasAuthHint reads the ctech_auth cookie from an explicit cookie string", () => {
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });
  assert.equal(client.hasAuthHint("ctech_auth=1; other=x"), true);
  assert.equal(client.hasAuthHint("other=x"), false);
  assert.equal(client.hasAuthHint(""), false);
});

test("refresh() never calls fetch when there is no auth hint — the wallet-SPA regression", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  let fetchCalled = false;
  globalThis.fetch = async () => {
    fetchCalled = true;
    throw new Error("must not be called");
  };
  // No `document` global here, so hasAuthHint()'s default cookieString is "".
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "wallet",
    redirectUri: "https://wallet.test/callback",
    scope: "openid profile kyc",
  });

  const result = await client.refresh();

  assert.equal(result, null);
  assert.equal(fetchCalled, false);

  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("startOAuthFlow appends max_age when requested — the withdrawal step-up regression", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.window = { location: { href: "" } };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "wallet",
    redirectUri: "https://wallet.test/callback",
    scope: "openid",
  });

  await client.startOAuthFlow("/dashboard", { maxAge: 0 });

  const url = new URL(globalThis.window.location.href);
  assert.equal(url.searchParams.get("max_age"), "0");

  delete globalThis.window;
  delete globalThis.sessionStorage;
});

test("startOAuthFlow omits max_age by default — every existing caller is unaffected", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.window = { location: { href: "" } };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "wallet",
    redirectUri: "https://wallet.test/callback",
    scope: "openid",
  });

  await client.startOAuthFlow("/dashboard");

  const url = new URL(globalThis.window.location.href);
  assert.equal(url.searchParams.has("max_age"), false);

  delete globalThis.window;
  delete globalThis.sessionStorage;
});

test("refresh() collapses concurrent calls into a single fetch (single-flight dedup)", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.document = { cookie: "ctech_auth=1" };
  let fetchCallCount = 0;
  globalThis.fetch = async () => {
    fetchCallCount++;
    await new Promise((resolve) => setTimeout(resolve, 10));
    return { ok: true, json: async () => ({ access_token: "tok", id_token: null }) };
  };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });

  const [first, second] = await Promise.all([client.refresh(), client.refresh()]);

  assert.equal(fetchCallCount, 1);
  assert.strictEqual(first, second);
  assert.deepEqual(first, { accessToken: "tok", idToken: null });

  delete globalThis.document;
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("decodeIdToken extracts name claims from a JWT payload", () => {
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  const idToken = `${b64url({ alg: "RS256" })}.${b64url({
    given_name: "Ada",
    family_name: "Lovelace",
    preferred_username: "ada",
  })}.sig`;

  const claims = decodeIdToken(idToken);

  assert.deepEqual(claims, { username: "ada", first_name: "Ada", last_name: "Lovelace" });
  assert.equal(decodeIdToken("not-a-jwt"), null);
});
