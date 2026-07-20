# @aoctech/auth-client

[![CI](https://github.com/artur-oliveira/ctech-oauth-client/actions/workflows/ci.yml/badge.svg)](https://github.com/artur-oliveira/ctech-oauth-client/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@aoctech/auth-client)](https://www.npmjs.com/package/@aoctech/auth-client)

Shared browser OAuth 2.0 + PKCE client for apps built on the [ctech-account](https://accounts.aoctech.app)
identity provider. One `OAuthClient` instance per app, config-only — no server, no framework dependency.

> Repo name is `ctech-oauth-client` on GitHub; published to npm as `@aoctech/auth-client`.
> Searching by either name should land here.

## Why this exists

Three SPAs (accounts, ctech-dfe, ctech-wallet) each carried their own ~200-line copy of the same OAuth
flow. They drifted: two of the three checked whether a session could plausibly exist (via the `ctech_auth`
hint cookie or a local revoked-flag) before firing a silent refresh — the third fired unconditionally on
every mount, including the very first visit of a browser that never had a session. That's a guaranteed
`POST /v1.0/token` failure on every cold visit, and it burns the same shared brute-force rate limit that
protects login and client-secret guessing on the IdP.

This package is the single implementation. `OAuthClient.refresh()` always checks the hint cookie and a
local revoked-state before touching the network, and de-duplicates concurrent calls (boot-time init and a
401 retry interceptor calling `refresh()` at the same instant share one request instead of firing two).

## Install

```bash
npm install @aoctech/auth-client
```

## Usage

```ts
import { OAuthClient } from "@aoctech/auth-client";

export const oauth = new OAuthClient({
  baseUrl: process.env.NEXT_PUBLIC_CTECH_URL!,
  clientId: process.env.NEXT_PUBLIC_CTECH_CLIENT_ID!,
  redirectUri: `${window.location.origin}/callback`,
  scope: "openid profile",
});

// Kick off login
await oauth.startOAuthFlow("/dashboard");

// On the /callback page
const { accessToken, idToken, returnTo } = await oauth.exchangeCode(code, state);

// Silent refresh — safe to call from app boot AND a 401 interceptor at once
const result = await oauth.refresh(); // null if not worth attempting or it failed

// Logout
await oauth.revoke();
oauth.endSessionRedirect("/login");
```

## API

- `hasAuthHint(cookieString?)` / `clearAuthHint()` — read/clear the `ctech_auth` marker cookie.
- `startOAuthFlow(returnTo?)` — redirects to `/v1.0/authorize` with a fresh PKCE pair.
- `exchangeCode(code, state)` — `authorization_code` grant.
- `refresh()` — guarded, single-flight `refresh_token` grant. Never throws.
- `revoke()` — best-effort `POST /v1.0/revoke`.
- `endSessionRedirect(returnTo?)` — RP-initiated logout via `/v1.0/auth/end-session`.
- `decodeIdToken(idToken)` — unverified payload decode, for display-only name claims.

Also exported standalone: `generatePKCE()`, `generateState()`, `decodeIdToken()`.

## Development

```bash
npm run build   # tsc -> dist/
npm test        # build + node's built-in test runner
```

## Releasing

`publish.yml` only fires on a published GitHub Release — a push to `main` alone never publishes
(it only runs `ci.yml`, which tests). Publishing uses npm's OIDC trusted publishing, so there's no
`NPM_TOKEN` secret to manage; provenance is generated automatically.

```bash
# 1. Bump "version" in package.json, then commit and push as usual
git commit -am "chore: release vX.Y.Z"
git push

# 2. Tag it and push the tag
git tag vX.Y.Z
git push --tags

# 3. Cut the release — this is what actually triggers the publish workflow
gh release create vX.Y.Z --generate-notes
```

## License

MIT

## Implementation reference (file:line) — audited

Anchors into `src/` (the dist is built from these; `src/index.ts:1-5` is the export surface):

- `OAuthClient` — `src/client.ts:18`. `startOAuthFlow(returnTo?, opts?)` `:114`; **step-up is the
  `opts.maxAge` seconds option** `:134-136` (there is no `startStepUpFlow` symbol). `exchangeCode`
  `:143`, `refresh()` `:182` (single-flight, never throws), `revoke()` `:230`, `endSessionRedirect`
  `:247`, `hasAuthHint` `:76` / `clearAuthHint` `:82`, `decodeIdToken` `:255`, `close()` `:39`.
- PKCE/state — `generatePKCE` `src/pkce.ts:14`, `generateState` `:22`.
- id_token decode — `decodeIdToken` `src/jwt.ts:17` → `UnverifiedIdTokenClaims` `src/jwt.ts:1`
  (`IdTokenClaims` `:10` is a deprecated alias; **no signature/nonce check**).
- Storage — `NamespacedStorage` `src/storage.ts:3` is **sessionStorage** (PKCE/ephemeral state only).
  Tokens are held by the IdP in **HttpOnly cookies** (`credentials:"include"` `src/client.ts:165`);
  this client is stateless w.r.t. tokens. Hypothesis that it "stores tokens in HttpOnly cookies" is
  inaccurate — the cookies are the IdP's.
- Config types — `OAuthClientConfig` `src/types.ts:1`, `TokenResult` `:14`.

