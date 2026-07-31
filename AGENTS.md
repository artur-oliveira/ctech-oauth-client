# AGENTS.md — ctech-oauth-client (npm `@aoctech/auth-client`)

**Reuse me, don't fork.** This is the single browser OAuth 2.0 + PKCE client for every CTech SPA
(accounts, dfe, wallet). If you are wiring a new SPA to ctech-account, import this — do not copy a
~200-line flow again (that drift is exactly what this package ended).

## Import

```ts
import { OAuthClient, generatePKCE, decodeIdToken } from "@aoctech/auth-client";
```

Repo dir is `ctech-oauth-client`; npm name is `@aoctech/auth-client`.

## Public API (anchored to file:line in `src/`)

- `OAuthClient` — `src/client.ts:18`. Construct once per app: `new OAuthClient(config)`
  (`constructor` `:25`; `OAuthClientConfig` `src/types.ts:1`).
  - `hasAuthHint(cookieString?)` `:76` / `clearAuthHint()` `:82` — read/clean the `ctech_auth`
    marker cookie the IdP sets on the parent domain. `refresh()` checks this first so a SPA with no
    session never burns the IdP's brute-force rate limit.
  - `startOAuthFlow(returnTo?, opts?)` `:114` — redirects to `/v1.0/authorize` with a fresh PKCE
    pair + `state` + `nonce`. **Step-up auth is the `opts.maxAge` (seconds) option** `:134-136`
    (pass `0` to force a fresh login). There is **no** separate `startStepUpFlow` symbol.
  - `exchangeCode(code, state)` `:143` — `authorization_code` grant; throws on state mismatch.
  - `refresh()` `:182` — guarded, single-flight `refresh_token` grant; **never throws**, returns
    `null` when not worth attempting/failed. Cross-tab dedup via `BroadcastChannel` `:27-33`.
  - `revoke()` `:230` — best-effort `POST /v1.0/revoke` (marks local revoked first).
  - `endSessionRedirect(returnTo?)` `:247` — RP logout via `/v1.0/auth/end-session`.
  - `decodeIdToken(idToken)` `:255` — **unverified** display-only name claims (see below).
  - `close()` `:39` — release the `BroadcastChannel` on teardown.
- `generatePKCE()` `src/pkce.ts:14`, `generateState()` `:22`.
- `decodeIdToken()` `src/jwt.ts:17` — returns `UnverifiedIdTokenClaims` `src/jwt.ts:1`. `IdTokenClaims`
  `:10` is a **deprecated** alias. Output has **no signature or nonce check** — display only.
- `TokenResult` `src/types.ts:14`, `OAuthClientConfig` `src/types.ts:1`.
- Exports surface: `src/index.ts:1-5`.

## Token storage — what is actually implemented

This client does **not** store access/refresh tokens. The IdP holds them in **HttpOnly cookies**
(`credentials: "include"` on `/v1.0/token` `src/client.ts:165`); this client persists only the
PKCE/ephemeral handshake state (`oauth_state`, `oauth_verifier`, `oauth_nonce`, `oauth_return_to`,
`auth_state`) in **sessionStorage** via `NamespacedStorage` `src/storage.ts:3`. Hypothesis that this
lib "stores tokens in HttpOnly cookies" is inaccurate — the HttpOnly cookies are the IdP's, set
server-side; this package is stateless w.r.t. tokens.

## Notes

- v1.1.0 added `BroadcastChannel` coordination + `close()` + `nonce` + `UnverifiedIdTokenClaims`
  rename (`CHANGELOG.md`).
- MIT licensed. Publish via npm OIDC trusted publishing on GitHub Release.

## Mandatory Documentation Policy

**Every code change MUST be documented.**

There are NO exceptions.

Any modification affecting behavior, architecture, APIs, integrations, configuration, deployment, security, business rules, or developer workflow MUST include the corresponding documentation update in the same change.
