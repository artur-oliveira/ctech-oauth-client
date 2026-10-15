# Changelog

## [1.4.1] - 2026-10-15

- Fix: a `refresh()` fired while `exchangeCode()` is in flight (an SPA's boot refresh racing its `/callback` page) now waits for the exchange and returns its token. Before, the refresh ran with the previous session's cookie and, finishing last, overwrote the new session's claims — a step-up login (`maxAge: 0`) came back with a stale `last_mfa_at` and the protected action kept answering step-up-required.

## [1.4.0] - 2026-10-06

- Optional expiresAt derives from valid expires_in for proactive refresh scheduling. Missing/invalid TTL preserves the legacy response shape. Scheduling metadata never grants authorization.
- Optional requestTimeoutMs bounds token fetch; omitted preserves existing behavior. Refresh timeouts retain transient retry and cross-tab singleflight semantics.

## [1.3.0] - 2026-09-06

- `refresh()` now retries an `OAuthTransientError` (network blip, throttling, timeout-like, or
  5xx failure during token refresh) up to 2 times with exponential backoff + jitter (300ms,
  600ms, capped at 1200ms) before giving up, all inside the same single-flight/Web-Locks-guarded
  attempt. A terminal failure (revoked/expired session) is never retried — it still resolves to
  `null` immediately. If every attempt is transient, `refresh()` still throws
  `OAuthTransientError` as before, so a sustained outage is still distinguishable from "logged
  out"; callers that already catch it are unaffected, they just see it less often.

## [1.2.0] - 2026-09-03

- Serialize refreshes across same-origin tabs with the Web Locks API and share
  the leader's token response instead of rotating the cookie again.
- Throw `OAuthTransientError` for network, throttling, timeout-like, and server
  failures so applications preserve the current session instead of logging out.

## [1.1.0] - 2026-07-18

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
