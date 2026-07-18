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
