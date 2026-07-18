# ctech-oauth-client Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:
> executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every audit finding attributable to this repo's code: untested single-flight
refresh dedup, no cross-tab coordination, `decodeIdToken()` output usable as an authz signal
by accident, missing `nonce`, and release/package hygiene drift (lockfile, stale artifact,
changelog, naming).

**Architecture:** No new files except a changelog and this plan/spec. All behavior changes
land in the existing three source files (`src/client.ts`, `src/jwt.ts`, `src/index.ts`).
Cross-tab coordination uses the platform's native `BroadcastChannel` (available in Node
> =18 and every evergreen browser this SDK targets) — no new dependency, no polyfill.

**Tech Stack:** TypeScript (ES2020 target, DOM lib), Node's built-in test runner
(`node --test`) against the compiled `dist/` output, no test framework, no mocking library.

## Global Constraints

- Scope is this repo (`ctech-oauth-client` / `@aoctech/auth-client`) only. Do not touch
  `ctech-account` or `ctech-account/ui` — their fixes are separate, cross-repo follow-ups
  (see spec's "Out of scope" section).
- No new runtime dependencies. `BroadcastChannel` and `MessageEvent` types come from the
  `DOM` lib already in `tsconfig.json:6`; no `@types/*` package needed.
- Backwards compatible: `IdTokenClaims` must stay a valid exported type name (deprecated
  alias), since all three consumers already import it.
- Every new test runs via the existing `npm test` script (`tsc -p tsconfig.json && node
  --test`) against compiled `dist/index.js` — same pattern as `test/client.test.js`'s
  existing 7 tests. No new test tooling.
- Any `OAuthClient` instance that opens a `BroadcastChannel` keeps the Node process alive
  until it's closed (confirmed: an unclosed `BroadcastChannel` prevents `node --test` from
  exiting) — every test that constructs a client from Task 8 onward must call
  `client.close()` in its cleanup.
- Ship all of this as `1.1.0` (see Task 9/10) once merged.

---

### Task 1: Test single-flight refresh dedup (spec R1)

The dedup already works (`src/client.ts:129-138`'s `inFlightRefresh` field) — it's just
never been asserted. This task adds the missing regression test only; no source change.

**Files:**

- Test: `test/client.test.js`

**Interfaces:**

- Consumes: `OAuthClient` (`src/client.ts`), already exported via `dist/index.js`.

- [ ] **Step 1: Write the test**

Add to `test/client.test.js` (after the existing `decodeIdToken` test):

```js
test("refresh() collapses concurrent calls into a single fetch (single-flight dedup)", async () => {
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.document = {cookie: "ctech_auth=1"};
    let fetchCallCount = 0;
    globalThis.fetch = async () => {
        fetchCallCount++;
        await new Promise((resolve) => setTimeout(resolve, 10));
        return {ok: true, json: async () => ({access_token: "tok", id_token: null})};
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
    assert.deepEqual(first, {accessToken: "tok", idToken: null});

    delete globalThis.document;
    delete globalThis.sessionStorage;
    delete globalThis.fetch;
});
```

- [ ] **Step 2: Run it and confirm it passes**

Run: `npm test`
Expected: all existing tests plus this new one PASS (dedup already works — this locks it in).

- [ ] **Step 3: Commit**

```bash
git add test/client.test.js
git commit -m "test: cover single-flight refresh dedup"
```

---

### Task 2: Cover remaining stateful methods with tests (spec R6)

`exchangeCode()`, `doRefresh()`'s branches (via `refresh()`), `revoke()`, and
`endSessionRedirect()` have zero coverage today. No source change — test-only task.

**Files:**

- Test: `test/client.test.js`

**Interfaces:**

- Consumes: `OAuthClient.startOAuthFlow`, `.exchangeCode`, `.refresh`, `.revoke`,
  `.endSessionRedirect` (`src/client.ts`); `client.storage.get/set(name)` — a plain JS
  property post-compile (TypeScript `private` is compile-time only, erased in `dist/`), used
  here only to assert on internal state, not part of the public API.

- [ ] **Step 1: Write `exchangeCode()` tests**

```js
test("exchangeCode() throws on state mismatch", async () => {
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.window = {location: {href: ""}};
    const client = new OAuthClient({
        baseUrl: "https://api.test",
        clientId: "test",
        redirectUri: "https://app.test/callback",
        scope: "openid",
    });
    await client.startOAuthFlow("/dashboard");

    await assert.rejects(() => client.exchangeCode("code123", "not-the-real-state"), /OAuth state mismatch/);

    delete globalThis.window;
    delete globalThis.sessionStorage;
});

test("exchangeCode() exchanges the code, clears oauth_* storage, and returns tokens + returnTo", async () => {
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.window = {location: {href: ""}};
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
        return {ok: true, json: async () => ({access_token: "tok", id_token: "idtok"})};
    };

    const result = await client.exchangeCode("code123", state);

    assert.deepEqual(result, {accessToken: "tok", idToken: "idtok", returnTo: "/dashboard"});
    assert.equal(client.storage.get("oauth_state"), null);
    assert.equal(client.storage.get("oauth_verifier"), null);
    assert.equal(client.storage.get("oauth_return_to"), null);
    assert.match(fetchBody, /grant_type=authorization_code/);

    delete globalThis.window;
    delete globalThis.sessionStorage;
    delete globalThis.fetch;
});

test("exchangeCode() throws with status and body on a non-2xx response", async () => {
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.window = {location: {href: ""}};
    const client = new OAuthClient({
        baseUrl: "https://api.test",
        clientId: "test",
        redirectUri: "https://app.test/callback",
        scope: "openid",
    });
    await client.startOAuthFlow("/dashboard");
    const state = new URL(globalThis.window.location.href).searchParams.get("state");

    globalThis.fetch = async () => ({ok: false, status: 400, text: async () => "invalid_grant"});

    await assert.rejects(
        () => client.exchangeCode("code123", state),
        /Token exchange failed \(400\): invalid_grant/,
    );

    delete globalThis.window;
    delete globalThis.sessionStorage;
    delete globalThis.fetch;
});
```

- [ ] **Step 2: Write `refresh()`/`doRefresh()` branch tests**

```js
test("refresh() sets auth_state to active and returns tokens on a 2xx response", async () => {
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.document = {cookie: "ctech_auth=1"};
    globalThis.fetch = async () => ({ok: true, json: async () => ({access_token: "tok", id_token: null})});
    const client = new OAuthClient({
        baseUrl: "https://api.test",
        clientId: "test",
        redirectUri: "https://app.test/callback",
        scope: "openid",
    });

    const result = await client.refresh();

    assert.deepEqual(result, {accessToken: "tok", idToken: null});
    assert.equal(client.storage.get("auth_state"), "active");

    delete globalThis.document;
    delete globalThis.sessionStorage;
    delete globalThis.fetch;
});

test("refresh() sets auth_state to revoked and returns null on a non-2xx response", async () => {
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.document = {cookie: "ctech_auth=1"};
    globalThis.fetch = async () => ({ok: false, status: 401, text: async () => "invalid_grant"});
    const client = new OAuthClient({
        baseUrl: "https://api.test",
        clientId: "test",
        redirectUri: "https://app.test/callback",
        scope: "openid",
    });

    const result = await client.refresh();

    assert.equal(result, null);
    assert.equal(client.storage.get("auth_state"), "revoked");

    delete globalThis.document;
    delete globalThis.sessionStorage;
    delete globalThis.fetch;
});

test("refresh() leaves auth_state untouched and returns null on a network error", async () => {
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.document = {cookie: "ctech_auth=1"};
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

    const result = await client.refresh();

    assert.equal(result, null);
    assert.equal(client.storage.get("auth_state"), "active");

    delete globalThis.document;
    delete globalThis.sessionStorage;
    delete globalThis.fetch;
});
```

- [ ] **Step 3: Write `revoke()` tests**

```js
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
    resolveFetch({ok: true});
    await revokePromise;

    delete globalThis.sessionStorage;
    delete globalThis.fetch;
});

test("refresh() started after revoke() returns null without calling fetch", async () => {
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.document = {cookie: "ctech_auth=1"};
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
    resolveRevokeFetch({ok: true});
    await revokePromise;

    delete globalThis.document;
    delete globalThis.sessionStorage;
    delete globalThis.fetch;
});
```

- [ ] **Step 4: Write `endSessionRedirect()` tests**

```js
test("endSessionRedirect() redirects to /v1.0/auth/end-session with default returnTo", () => {
    globalThis.window = {location: {href: "", origin: "https://app.test"}};
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

    delete globalThis.window;
});

test("endSessionRedirect() honors a custom returnTo", () => {
    globalThis.window = {location: {href: "", origin: "https://app.test"}};
    const client = new OAuthClient({
        baseUrl: "https://api.test",
        clientId: "test",
        redirectUri: "https://app.test/callback",
        scope: "openid",
    });

    client.endSessionRedirect("/goodbye");

    const url = new URL(globalThis.window.location.href);
    assert.equal(url.searchParams.get("post_logout_redirect_uri"), "https://app.test/goodbye");

    delete globalThis.window;
});
```

- [ ] **Step 5: Run all tests and confirm they pass**

Run: `npm test`
Expected: PASS — every test added in Steps 1-4.

- [ ] **Step 6: Commit**

```bash
git add test/client.test.js
git commit -m "test: cover exchangeCode, refresh branches, revoke, endSessionRedirect"
```

---

### Task 3: Mark `decodeIdToken()` output as unverified in the type (spec R4)

**Files:**

- Modify: `src/jwt.ts`
- Modify: `src/index.ts`

**Interfaces:**

- Produces: `UnverifiedIdTokenClaims` (canonical type, same shape as today's
  `IdTokenClaims`), `IdTokenClaims` (deprecated alias, `= UnverifiedIdTokenClaims`).
  `decodeIdToken(idToken: string): UnverifiedIdTokenClaims | null` (same runtime behavior,
  new return type name only).

- [ ] **Step 1: Rename the type in `src/jwt.ts` and add the deprecated alias**

Replace the top of `src/jwt.ts` (lines 1-10):

```ts
export interface UnverifiedIdTokenClaims {
  username?: string;
  first_name?: string;
  last_name?: string;
}

/** @deprecated Renamed to {@link UnverifiedIdTokenClaims} to make explicit that
 * `decodeIdToken()`'s output has no signature check and no nonce check — this alias exists
 * only so existing imports keep compiling. */
export type IdTokenClaims = UnverifiedIdTokenClaims;

/** Decodes an id_token payload client-side. UNVERIFIED: no signature check and no nonce
 * check are performed — the token came straight from the IdP over TLS at exchange time,
 * this is for display only (e.g. showing a name). Never use this output for an
 * authorization decision. Resource-server access tokens are audience-restricted and can't
 * carry these name claims, so consumers read them from the id_token instead. */
export function decodeIdToken(idToken: string): UnverifiedIdTokenClaims | null {
```

Leave the function body (lines 12-29 in the current file) unchanged.

- [ ] **Step 2: Update `src/index.ts`'s type export**

In `src/index.ts`, replace:

```ts
export type {IdTokenClaims} from "./jwt.js";
```

with:

```ts
export type {UnverifiedIdTokenClaims, IdTokenClaims} from "./jwt.js";
```

- [ ] **Step 3: Build and run tests**

Run: `npm test`
Expected: `tsc` compiles with no errors (confirms both type names resolve), and the
existing `decodeIdToken` test in `test/client.test.js` still PASSes unchanged.

- [ ] **Step 4: Commit**

```bash
git add src/jwt.ts src/index.ts
git commit -m "refactor: rename IdTokenClaims to UnverifiedIdTokenClaims, keep deprecated alias"
```

---

### Task 4: Add `nonce` to the authorization request (spec R5)

**Files:**

- Modify: `src/client.ts`
- Test: `test/client.test.js`

**Interfaces:**

- Consumes: `generateState()` (`src/pkce.ts:22-24`) — reused as-is for the nonce value,
  same 32-hex-char shape.
- Produces: `startOAuthFlow()` now also sets `oauth_nonce` in storage and appends a `nonce`
  query param. No signature change to `startOAuthFlow`'s public API.

- [ ] **Step 1: Write the test first**

Add to `test/client.test.js`:

```js
test("startOAuthFlow includes a nonce param distinct from state", async () => {
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.window = {location: {href: ""}};
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

    delete globalThis.window;
    delete globalThis.sessionStorage;
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npm test`
Expected: FAIL — `nonce` is `null` (param doesn't exist yet).

- [ ] **Step 3: Implement — add nonce generation and storage in `src/client.ts`**

In `startOAuthFlow` (`src/client.ts:64-86`), change:

```ts
  async
startOAuthFlow(returnTo = "/", opts ? : {maxAge? : number})
:
Promise < void > {
  const state = generateState();
  const {codeVerifier, codeChallenge} = await generatePKCE();

  this.storage.set("oauth_state", state);
  this.storage.set("oauth_verifier", codeVerifier);
  this.storage.set("oauth_return_to", returnTo);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: this.config.clientId,
    redirect_uri: this.config.redirectUri,
    scope: this.config.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
```

to:

```ts
  async
startOAuthFlow(returnTo = "/", opts ? : {maxAge? : number})
:
Promise < void > {
  const state = generateState();
  const nonce = generateState();
  const {codeVerifier, codeChallenge} = await generatePKCE();

  this.storage.set("oauth_state", state);
  this.storage.set("oauth_nonce", nonce);
  this.storage.set("oauth_verifier", codeVerifier);
  this.storage.set("oauth_return_to", returnTo);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: this.config.clientId,
    redirect_uri: this.config.redirectUri,
    scope: this.config.scope,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
```

Also update the method's doc comment (`src/client.ts:54-63`) to add one line: "Also sends a
`nonce` (OIDC-standard) so the IdP can enforce id_token replay protection server-side —
this client does not itself validate it back, matching how `decodeIdToken()` performs no
signature check (see `UnverifiedIdTokenClaims`)."

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test`
Expected: PASS, and all prior tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add src/client.ts test/client.test.js
git commit -m "feat: send a nonce param on the authorization request"
```

---

### Task 5: Cross-tab refresh coordination + revoke propagation via BroadcastChannel (spec R2, R3)

Reduces (does not eliminate — the real fix is server-side, out of scope) how often two tabs
hit `/v1.0/token` at once, and propagates `revoke()` to sibling tabs immediately.

**Files:**

- Modify: `src/client.ts`
- Test: `test/client.test.js`

**Interfaces:**

- Produces: `OAuthClient.close(): void` — new public method, closes this instance's
  `BroadcastChannel`. No-op if `BroadcastChannel` is unavailable.
- Internal: `BroadcastMessage` union type, `onBroadcastMessage`, `waitForPeerRefresh` —
  private, not exported.

- [ ] **Step 1: Write the peer-coordination test first**

Add to `test/client.test.js`:

```js
test("refresh() waits for a peer tab's in-flight refresh instead of firing its own fetch", async () => {
    const prefix = `peer-refresh-${Math.random().toString(36).slice(2)}`;
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.document = {cookie: "ctech_auth=1"};
    let fetchCallCount = 0;
    let resolveFirstFetch;
    const firstFetchGate = new Promise((resolve) => {
        resolveFirstFetch = resolve;
    });
    globalThis.fetch = async () => {
        fetchCallCount++;
        if (fetchCallCount === 1) await firstFetchGate;
        return {ok: true, json: async () => ({access_token: `tok-${fetchCallCount}`, id_token: null})};
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
    assert.deepEqual(resultA, {accessToken: "tok-1", idToken: null});

    const resultB = await refreshB;
    assert.equal(fetchCallCount, 2, "tab B fires its own fetch once tab A's refresh completes");
    assert.deepEqual(resultB, {accessToken: "tok-2", idToken: null});

    tabA.close();
    tabB.close();
    delete globalThis.document;
    delete globalThis.sessionStorage;
    delete globalThis.fetch;
});

test("revoke() in one tab marks a sibling tab as revoked", async () => {
    const prefix = `peer-revoke-${Math.random().toString(36).slice(2)}`;
    globalThis.sessionStorage = makeSessionStorage();
    globalThis.document = {cookie: "ctech_auth=1"};
    let refreshFetchCalled = false;
    globalThis.fetch = async (_url, init) => {
        if (init?.body?.includes?.("grant_type=refresh_token")) refreshFetchCalled = true;
        return {ok: true};
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm test`
Expected: FAIL — `fetchCallCount` reaches 2 before tab A resolves (no peer coordination
yet), and tab B's `refresh()` after tab A's `revoke()` still calls fetch (no cross-tab
revoke propagation yet). `tabA.close`/`tabB.close` will also fail (`close` doesn't exist
yet) — that's expected at this stage.

- [ ] **Step 3: Implement — add BroadcastChannel coordination to `src/client.ts`**

Add near the top of `src/client.ts`, after the existing constants (after line 8):

```ts
type BroadcastMessage =
  | { type: "refresh-start" }
  | { type: "refresh-done"; ok: boolean }
  | { type: "revoked" };

const PEER_REFRESH_TIMEOUT_MS = 5000;
```

Add a field next to `inFlightRefresh` (`src/client.ts:16`):

```ts
  private readonly
broadcast: BroadcastChannel | null;
private
peerRefreshing = false;
private
peerDoneWaiters: Array<() => void> = [];
```

Replace the constructor (`src/client.ts:18-20`):

```ts
  constructor(private
readonly
config: OAuthClientConfig
)
{
  this.storage = new NamespacedStorage(config.storagePrefix ?? config.clientId);
  this.broadcast =
    typeof BroadcastChannel !== "undefined"
      ? new BroadcastChannel(`ctech-oauth:${config.storagePrefix ?? config.clientId}`)
      : null;
  this.broadcast?.addEventListener("message", (event: MessageEvent<BroadcastMessage>) => {
    this.onBroadcastMessage(event.data);
  });
}

/** Closes this instance's cross-tab BroadcastChannel. Call on teardown (route unmount,
 * end of a test) to release the underlying channel — an unclosed channel keeps the page
 * (or a Node process, e.g. in tests) alive. No-op if BroadcastChannel isn't available. */
close()
:
void {
  this.broadcast?.close();
}

private
onBroadcastMessage(message
:
BroadcastMessage
):
void {
  if(message.type === "refresh-start"
)
{
  this.peerRefreshing = true;
  return;
}
if (message.type === "revoked") {
  this.setAuthState(AUTH_STATE_REVOKED);
}
this.peerRefreshing = false;
const waiters = this.peerDoneWaiters;
this.peerDoneWaiters = [];
waiters.forEach((resolve) => resolve());
}

private
waitForPeerRefresh()
:
Promise < void > {
  if(!
this.peerRefreshing
)
return Promise.resolve();
return new Promise((resolve) => {
  const timer = setTimeout(resolve, PEER_REFRESH_TIMEOUT_MS);
  this.peerDoneWaiters.push(() => {
    clearTimeout(timer);
    resolve();
  });
});
}
```

Replace `refresh()` (`src/client.ts:129-138`):

```ts
  async
refresh()
:
Promise < TokenResult | null > {
  if(this.isRevoked()
)
return null;
if (!this.hasAuthHint()) return null;
if (this.inFlightRefresh) return this.inFlightRefresh;

if (this.peerRefreshing) {
  await this.waitForPeerRefresh();
  if (this.isRevoked()) return null;
  if (this.inFlightRefresh) return this.inFlightRefresh;
}

this.broadcast?.postMessage({type: "refresh-start"} satisfies BroadcastMessage);
this.inFlightRefresh = this.doRefresh()
  .then((result) => {
    this.broadcast?.postMessage({type: "refresh-done", ok: result != null} satisfies BroadcastMessage);
    return result;
  })
  .finally(() => {
    this.inFlightRefresh = null;
  });
return this.inFlightRefresh;
}
```

Replace `revoke()` (`src/client.ts:165-176`):

```ts
  async
revoke()
:
Promise < void > {
  this.setAuthState(AUTH_STATE_REVOKED);
  this.broadcast?.postMessage({type: "revoked"} satisfies BroadcastMessage);
  try {
    await fetch(`${this.config.baseUrl}/v1.0/revoke`, {
      method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      credentials: "include",
    });
  } catch {
    // Best-effort — the local revoke already stops future refreshes.
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: PASS — both new tests plus every test from Tasks 1-4.

- [ ] **Step 5: Add `close()` cleanup to every earlier test that constructs a client**

Every test added in Tasks 1, 2, and 4 (and the three pre-existing tests that construct a
client: `hasAuthHint`, the `wallet-SPA` regression, both `startOAuthFlow` tests) now opens a
`BroadcastChannel` via the constructor. Add `client.close();` (or `tabA.close(); tabB.close();`
where applicable) right before each test's existing `delete globalThis...` cleanup lines.

- [ ] **Step 6: Run the full suite one more time**

Run: `npm test`
Expected: PASS, and the process exits on its own (no hang from an unclosed channel).

- [ ] **Step 7: Commit**

```bash
git add src/client.ts test/client.test.js
git commit -m "feat: coordinate refresh and revoke across tabs via BroadcastChannel"
```

---

### Task 6: Regenerate `package-lock.json` (spec R7)

**Files:**

- Modify: `package-lock.json`

- [ ] **Step 1: Regenerate**

Run: `npm install`

- [ ] **Step 2: Verify**

Run: `grep -A1 '"name"' package-lock.json | head -4`
Expected: `"name": "@aoctech/auth-client"` and a `"version"` matching `package.json` (not
`ctech-oauth-client` / `0.1.0`).

- [ ] **Step 3: Commit**

```bash
git add package-lock.json
git commit -m "chore: regenerate package-lock.json to match package.json"
```

---

### Task 7: Package hygiene cleanup (spec R8, R9, R10)

**Files:**

- Delete: `aoctech-auth-client-0.1.0.tgz`
- Create: `CHANGELOG.md`
- Modify: `README.md`

- [ ] **Step 1: Delete the stale build artifact**

Run: `rm aoctech-auth-client-0.1.0.tgz`

- [ ] **Step 2: Add `CHANGELOG.md`**

Create `CHANGELOG.md`:

```markdown
# Changelog

## [Unreleased]
- Cross-tab refresh/revoke coordination via `BroadcastChannel`, plus a new `close()` method.
- `nonce` param added to the authorization request.
- `decodeIdToken()`'s return type renamed to `UnverifiedIdTokenClaims` (`IdTokenClaims` kept
  as a deprecated alias).
- Test coverage added for the single-flight refresh dedup, `exchangeCode()`,
  `refresh()`/`doRefresh()` branches, `revoke()`, and `endSessionRedirect()`.

## [1.0.1] - 2026-07-17
- Added `max_age` param to `startOAuthFlow()` for step-up re-authentication (e.g. a
  withdrawal requiring a fresh login).
- Added the `repository` field to `package.json`, required by npm provenance verification.

## [1.0.0] - 2026-07-17
- Renamed the package from `ctech-oauth-client` to `@aoctech/auth-client`.

## [0.1.0] - 2026-07-17
- Initial release: PKCE (S256) authorization code flow, CSRF `state` handling, guarded
  single-flight `refresh()`, `revoke()`, `endSessionRedirect()`, unverified `decodeIdToken()`.
- CI: test-on-push, publish-on-GitHub-Release using npm OIDC trusted publishing.
```

- [ ] **Step 3: Add the naming note to `README.md`**

In `README.md`, after line 7 (the blank line following the "Shared browser OAuth 2.0 + PKCE
client..." paragraph) and before line 9 (`## Why this exists`), insert:

```markdown
> Repo name is `ctech-oauth-client` on GitHub; published to npm as `@aoctech/auth-client`.
> Searching by either name should land here.

```

- [ ] **Step 4: Commit**

```bash
git add -A CHANGELOG.md README.md
git status
git commit -m "chore: add changelog, drop stale tgz, note repo/package naming"
```

(The `git add -A` here is scoped by the preceding `rm` and file edits only — run `git
status` first, as shown, to confirm no other untracked files are picked up before
committing.)

---

## Self-Review Notes

- **Spec coverage:** R1→Task 1, R2/R3→Task 5, R4→Task 3, R5→Task 4, R6→Task 2, R7→Task 6,
  R8/R9/R10→Task 7. All ten requirements have a task.
- **Type consistency:** `UnverifiedIdTokenClaims` (Task 3) is introduced before Task 4's
  doc-comment reference to it and Task 5's use of `BroadcastMessage`/`close()` — no forward
  references to undefined names across tasks.
- **Ordering:** test-only tasks (1, 2) run before source changes (3, 4, 5) so the safety net
  is in place first; 3 and 4 are independent and could run in either order but 4 is placed
  after 3 since both touch `src/client.ts`'s doc comments in the same neighborhood; 5 is last
  among source changes since it's the highest-risk change and benefits most from the prior
  tasks' test coverage already being in place; hygiene tasks (6, 7) are last since they're
  independent of everything else.

## Execution Handoff

Plan complete and saved to `docs/plans/2026-07-18-audit-remediation.md`. Two execution
options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between
   tasks, fast iteration.
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch
   execution with checkpoints.

Which approach?
