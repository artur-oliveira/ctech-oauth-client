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
  client.close();
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

  client.close();
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

  client.close();
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

  client.close();
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

  client.close();
  delete globalThis.document;
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("exchangeCode() throws on state mismatch", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.window = { location: { href: "" } };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });
  await client.startOAuthFlow("/dashboard");

  await assert.rejects(() => client.exchangeCode("code123", "not-the-real-state"), /OAuth state mismatch/);

  client.close();
  delete globalThis.window;
  delete globalThis.sessionStorage;
});

test("exchangeCode() exchanges the code, clears oauth_* storage, and returns tokens + returnTo", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.window = { location: { href: "" } };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });
  await client.startOAuthFlow("/dashboard");
  const state = new URL(globalThis.window.location.href).searchParams.get("state");

  let fetchBody;
  globalThis.fetch = async (_url, init) => {
    fetchBody = init.body;
    return { ok: true, json: async () => ({ access_token: "tok", id_token: "idtok" }) };
  };

  const result = await client.exchangeCode("code123", state);

  assert.deepEqual(result, { accessToken: "tok", idToken: "idtok", returnTo: "/dashboard" });
  assert.equal(client.storage.get("oauth_state"), null);
  assert.equal(client.storage.get("oauth_verifier"), null);
  assert.equal(client.storage.get("oauth_return_to"), null);
  assert.match(fetchBody, /grant_type=authorization_code/);

  client.close();
  delete globalThis.window;
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("exchangeCode() throws with status and body on a non-2xx response", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.window = { location: { href: "" } };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });
  await client.startOAuthFlow("/dashboard");
  const state = new URL(globalThis.window.location.href).searchParams.get("state");

  globalThis.fetch = async () => ({ ok: false, status: 400, text: async () => "invalid_grant" });

  await assert.rejects(
    () => client.exchangeCode("code123", state),
    /Token exchange failed \(400\): invalid_grant/,
  );

  client.close();
  delete globalThis.window;
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("refresh() sets auth_state to active and returns tokens on a 2xx response", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.document = { cookie: "ctech_auth=1" };
  globalThis.fetch = async () => ({ ok: true, json: async () => ({ access_token: "tok", id_token: null }) });
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });

  const result = await client.refresh();

  assert.deepEqual(result, { accessToken: "tok", idToken: null });
  assert.equal(client.storage.get("auth_state"), "active");

  client.close();
  delete globalThis.document;
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("refresh() sets auth_state to revoked and returns null on a terminal 4xx response", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.document = { cookie: "ctech_auth=1" };
  globalThis.fetch = async () => ({ ok: false, status: 401, text: async () => "invalid_grant" });
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });

  const result = await client.refresh();

  assert.equal(result, null);
  assert.equal(client.storage.get("auth_state"), "revoked");

  client.close();
  delete globalThis.document;
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("refresh() leaves auth_state untouched and throws on a network error", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.document = { cookie: "ctech_auth=1" };
  globalThis.fetch = async () => {
    throw new Error("network down");
  };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });
  client.storage.set("auth_state", "active");

  await assert.rejects(() => client.refresh(), { name: "OAuthTransientError" });
  assert.equal(client.storage.get("auth_state"), "active");

  client.close();
  delete globalThis.document;
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("refresh() leaves auth_state active and throws on a retryable server response", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.document = { cookie: "ctech_auth=1" };
  globalThis.fetch = async () => ({ ok: false, status: 503 });
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });
  client.storage.set("auth_state", "active");

  await assert.rejects(() => client.refresh(), { name: "OAuthTransientError", status: 503 });
  assert.equal(client.storage.get("auth_state"), "active");

  client.close();
  delete globalThis.document;
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("revoke() sets auth_state to revoked before the network call resolves", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  let resolveFetch;
  globalThis.fetch = () => new Promise((resolve) => {
    resolveFetch = resolve;
  });
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });

  const revokePromise = client.revoke();

  assert.equal(client.storage.get("auth_state"), "revoked");
  resolveFetch({ ok: true });
  await revokePromise;

  client.close();
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("refresh() started after revoke() returns null without calling fetch", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.document = { cookie: "ctech_auth=1" };
  let resolveRevokeFetch;
  let refreshFetchCalled = false;
  globalThis.fetch = (_url, init) => {
    if (init?.body?.includes?.("grant_type=refresh_token")) {
      refreshFetchCalled = true;
    }
    return new Promise((resolve) => {
      resolveRevokeFetch = resolve;
    });
  };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });

  const revokePromise = client.revoke();
  const result = await client.refresh();

  assert.equal(result, null);
  assert.equal(refreshFetchCalled, false);
  resolveRevokeFetch({ ok: true });
  await revokePromise;

  client.close();
  delete globalThis.document;
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("endSessionRedirect() redirects to /v1.0/auth/end-session with default returnTo", () => {
  globalThis.window = { location: { href: "", origin: "https://app.test" } };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });

  client.endSessionRedirect();

  const url = new URL(globalThis.window.location.href);
  assert.equal(url.origin + url.pathname, "https://api.test/v1.0/auth/end-session");
  assert.equal(url.searchParams.get("client_id"), "test");
  assert.equal(url.searchParams.get("post_logout_redirect_uri"), "https://app.test/login");

  client.close();
  delete globalThis.window;
});

test("endSessionRedirect() honors a custom returnTo", () => {
  globalThis.window = { location: { href: "", origin: "https://app.test" } };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });

  client.endSessionRedirect("/goodbye");

  const url = new URL(globalThis.window.location.href);
  assert.equal(url.searchParams.get("post_logout_redirect_uri"), "https://app.test/goodbye");

  client.close();
  delete globalThis.window;
});

test("startOAuthFlow includes a nonce param distinct from state", async () => {
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.window = { location: { href: "" } };
  const client = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
  });

  await client.startOAuthFlow("/dashboard");

  const url = new URL(globalThis.window.location.href);
  const nonce = url.searchParams.get("nonce");
  const state = url.searchParams.get("state");
  assert.match(nonce, /^[0-9a-f]{32}$/);
  assert.notEqual(nonce, state);

  client.close();
  delete globalThis.window;
  delete globalThis.sessionStorage;
});

test("refresh() waits for a peer tab's in-flight refresh instead of firing its own fetch", async () => {
  const prefix = `peer-refresh-${Math.random().toString(36).slice(2)}`;
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.document = { cookie: "ctech_auth=1" };
  let fetchCallCount = 0;
  let resolveFirstFetch;
  const firstFetchGate = new Promise((resolve) => {
    resolveFirstFetch = resolve;
  });
  globalThis.fetch = async () => {
    fetchCallCount++;
    if (fetchCallCount === 1) await firstFetchGate;
    return { ok: true, json: async () => ({ access_token: `tok-${fetchCallCount}`, id_token: null }) };
  };

  const tabA = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
    storagePrefix: prefix,
  });
  const tabB = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
    storagePrefix: prefix,
  });

  const refreshA = tabA.refresh();
  await new Promise((resolve) => setTimeout(resolve, 10)); // let tab B's listener see "refresh-start"
  const refreshB = tabB.refresh();
  await new Promise((resolve) => setTimeout(resolve, 10));

  assert.equal(fetchCallCount, 1, "tab B must not fire its own fetch while tab A is refreshing");

  resolveFirstFetch();
  const resultA = await refreshA;
  assert.deepEqual(resultA, { accessToken: "tok-1", idToken: null });

  const resultB = await refreshB;
  assert.equal(fetchCallCount, 1, "tab B reuses the result published by tab A");
  assert.deepEqual(resultB, { accessToken: "tok-1", idToken: null });

  tabA.close();
  tabB.close();
  delete globalThis.document;
  delete globalThis.sessionStorage;
  delete globalThis.fetch;
});

test("revoke() in one tab marks a sibling tab as revoked", async () => {
  const prefix = `peer-revoke-${Math.random().toString(36).slice(2)}`;
  globalThis.sessionStorage = makeSessionStorage();
  globalThis.document = { cookie: "ctech_auth=1" };
  let refreshFetchCalled = false;
  globalThis.fetch = async (_url, init) => {
    if (init?.body?.includes?.("grant_type=refresh_token")) refreshFetchCalled = true;
    return { ok: true };
  };

  const tabA = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
    storagePrefix: prefix,
  });
  const tabB = new OAuthClient({
    baseUrl: "https://api.test",
    clientId: "test",
    redirectUri: "https://app.test/callback",
    scope: "openid",
    storagePrefix: prefix,
  });

  await tabA.revoke();
  await new Promise((resolve) => setTimeout(resolve, 10)); // let tab B's listener see "revoked"

  const resultB = await tabB.refresh();

  assert.equal(resultB, null);
  assert.equal(refreshFetchCalled, false);

  tabA.close();
  tabB.close();
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
