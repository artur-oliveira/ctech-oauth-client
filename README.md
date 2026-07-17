# @aoctech/auth-client

Shared browser OAuth 2.0 + PKCE client for apps built on the [ctech-account](https://accounts.aoctech.app)
identity provider. One `OAuthClient` instance per app, config-only — no server, no framework dependency.

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

## License

MIT
