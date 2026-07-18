# ctech-oauth-client Audit Remediation — Spec

Source: `~/Documents/Projects/Ctech/_analysis/ctech-oauth-client.md` and `GENERAL-REPORT.md`
(2026-07 CTech engineering audit). Scope: this repo (`@aoctech/auth-client`) only. Findings
that require changes in other repos (`ctech-account` server, `ctech-account/ui`) are listed
under **Out of scope** with the cross-repo action needed — not built here.

## Context

Audit verdict: good fundamentals (PKCE, CSRF state, httpOnly refresh cookie), but the
package's one headline feature — single-flight refresh dedup — is untested, doesn't cover
cross-tab, and the package has drifted release hygiene (stale lockfile, no changelog, no
tgz cleanup). This spec closes every finding attributable to this repo's code.

## Goals

- Test the concurrency guarantee the README already claims (single-tab single-flight).
- Reduce (client-side) the chance of the cross-tab refresh race reaching the IdP, and
  propagate revocation across tabs immediately instead of waiting for a 401.
- Stop `decodeIdToken()` output from being usable as an authz signal by accident.
- Cover every stateful method (`exchangeCode`, `doRefresh` branches, `revoke`,
  `endSessionRedirect`) with tests.
- Fix release/package hygiene: lockfile drift, stale artifact, changelog, naming note.

## Non-goals

- Fixing the server-side `RotateClientToken` race in `ctech-account` (no CAS/lock on
  refresh-token rotation) — that's a `ctech-account` repo change. See Out of scope.
- Removing the `ctech-account/ui` SDK bypass in `query-provider.tsx` — that's a
  `ctech-account/ui` repo change. See Out of scope.
- Full id_token signature verification (would need JWKS fetch + caching — a real feature,
  not implied by any finding; the finding only asks that unverified output can't be
  mistaken for verified).
- Any lint rule/codemod to stop other repos from hand-rolling token calls — enforcement
  lives in the consumer repos' CI, not here.

## Requirements

### R1 — Test single-flight refresh dedup (P0)

Two concurrent `refresh()` calls on one `OAuthClient` instance must collapse into exactly
one `fetch` to `/v1.0/token`, and both callers must receive the same resolved value.

**Acceptance:** new test in `test/client.test.js` that sets a valid auth hint cookie, mocks
`fetch` with a counter, fires `client.refresh()` twice without awaiting between calls,
awaits both, and asserts `fetchCallCount === 1` and both results are `===` (same object
reference, since `inFlightRefresh` is shared).

### R2 — Cross-tab refresh coordination via `BroadcastChannel`

Mitigate (not eliminate — the real fix is server-side, see Out of scope) the cross-tab
race: before calling `doRefresh()`, a tab should check whether a sibling tab is already
mid-refresh and, if so, await that outcome instead of also calling `/v1.0/token`.

**Design:** one `BroadcastChannel` per `storagePrefix` (mirrors the existing
`NamespacedStorage` prefix so two different `OAuthClient` configs on the same domain don't
cross-talk).

- Before `doRefresh()`, post `{type: "refresh-start"}`.
- On completion, post `{type: "refresh-done", ok: boolean}`.
- A tab that receives `refresh-start` while it has no in-flight refresh of its own sets a
  short-lived "peer refreshing" flag and, if it was about to call `refresh()`, waits for the
  matching `refresh-done` instead (bounded by a timeout, e.g. 5s, in case the other tab
  closes mid-request) and treats a timeout the same as a failed refresh (returns `null`).
- Falls back to today's single-tab-only behavior when `BroadcastChannel` is undefined (old
  Safari, non-browser test environments) — feature-detect, don't polyfill.

**Acceptance:** new test simulating two `OAuthClient` instances sharing a fake
`BroadcastChannel` (an in-memory pub/sub double, since Node's `--test` runner has no real
`BroadcastChannel` wiring across instances by default) — second instance's `refresh()`
does not call `fetch` while the first's is in flight, and resolves once the first posts
`refresh-done`.

### R3 — Cross-tab revoke propagation

`revoke()` in one tab must mark sibling tabs' `auth_state` as revoked immediately, not wait
for their next 401.

**Design:** reuse the `BroadcastChannel` from R2. `revoke()` posts
`{type: "revoked"}` after setting local state. Every tab listens and, on receipt, calls
`this.setAuthState(AUTH_STATE_REVOKED)` locally (note: `sessionStorage` is NOT shared
across tabs, so each tab's own storage must still be updated explicitly — the broadcast is
the only cross-tab signal available).

**Acceptance:** test with two client instances sharing the fake channel — calling
`revoke()` on instance A results in instance B's next `refresh()` returning `null` without
a `fetch` call (because `isRevoked()` now reads true).

### R4 — Mark `decodeIdToken()` output as unverified in the type, not just a comment

Rename the exported type from `IdTokenClaims` to `UnverifiedIdTokenClaims` (keep
`IdTokenClaims` as a deprecated re-export alias for one minor version to avoid a breaking
change for the three consumers already importing it) and expand the existing doc comment
to state explicitly: no signature check, no nonce check, must not be used for an authz
decision.

**Acceptance:** `src/jwt.ts` exports both `UnverifiedIdTokenClaims` (canonical) and
`IdTokenClaims` (`@deprecated` JSDoc, `export type IdTokenClaims = UnverifiedIdTokenClaims`),
`src/index.ts` re-exports both, existing `decodeIdToken` test still passes unchanged.

### R5 — Add `nonce` to the auth code flow

`startOAuthFlow` generates and stores a `nonce` (reuse `generateState()`'s generator — same
shape, different storage key `oauth_nonce`) and includes it as the `nonce` query param.
`exchangeCode` does not need to validate it against the id_token (no signature verification
happens client-side per R4/Non-goals) — generating and sending it is what lets the IdP
enforce replay protection server-side per OIDC, which is the actual gap the audit flags.
Document in the JSDoc that nonce validation is the IdP's responsibility, matching how
`state` is already this client's responsibility.

**Acceptance:** new test asserting `startOAuthFlow` appends a `nonce` param of the same
format as `state` (32 hex chars), and that it differs from `state` on the same call.

### R6 — Cover remaining stateful methods with tests

Add tests for:

- `exchangeCode()`: state-mismatch throws `"OAuth state mismatch"`; happy path returns
  `{accessToken, idToken, returnTo}` and clears the three `oauth_*` storage keys; non-2xx
  response throws with status + body text.
- `doRefresh()` via `refresh()`: 2xx response sets `auth_state` to `"active"` and returns
  `{accessToken, idToken}`; non-2xx sets `auth_state` to `"revoked"` and returns `null`;
  thrown/network error leaves `auth_state` untouched and returns `null`.
- `revoke()`: sets `auth_state` to `"revoked"` before the network call resolves (assert via
  a `fetch` mock that resolves after a microtask tick — state must already be `"revoked"`
  by the time `revoke()`'s promise is still pending), and a `refresh()` call issued after
  `revoke()` starts (before its `fetch` resolves) returns `null` without calling `fetch`.
- `endSessionRedirect()`: sets `window.location.href` to
  `${baseUrl}/v1.0/auth/end-session?client_id=...&post_logout_redirect_uri=...` with the
  default and a custom `returnTo`.

**Acceptance:** all listed cases exist as named tests in `test/client.test.js` and pass.

### R7 — Regenerate `package-lock.json`

Run `npm install` so the lockfile's `name`/`version`/`engines` match `package.json`
(`@aoctech/auth-client`, `1.0.1`+, `node >=24`).

**Acceptance:** `package-lock.json`'s root `name`/`version` match `package.json`; `npm ci`
succeeds.

### R8 — Delete stale build artifact

Delete `aoctech-auth-client-0.1.0.tgz` from the working tree (untracked cruft, confirmed
not in git).

### R9 — Add `CHANGELOG.md`

One entry per existing tag (`0.1.0`, `1.0.0`, `1.0.1`) reconstructed from `git log`/tag
diffs, plus a new entry for the version this spec's changes ship under. Keep-a-changelog
style headings (`## [1.1.0] - <date>` etc.) are enough — no tooling needed for 4 entries.

### R10 — Reconcile naming in README

Add a one-line note near the top of `README.md`: repo is `ctech-oauth-client` on GitHub,
published as `@aoctech/auth-client` on npm, so cross-repo searches by either name land
here.

## Out of scope — cross-repo follow-ups (not built by this spec)

- **`ctech-account` server**: add a CAS/conditional-update or per-session mutex to
  `RotateClientToken` (`internal/domain/session/service.go:136-174`) so two requests
  presenting the same refresh-token hash can't both succeed with different new tokens.
  This is the actual fix for the cross-tab race; R2 above only reduces how often two tabs
  hit the server at once, it can't fully close the race from the client alone.
- **`ctech-account/ui`**: replace the hand-rolled `axios.post(/v1.0/token)` in
  `src/providers/query-provider.tsx:37-79` with `oauthClient.refresh()`.
- **`ctech-account` / `ctech-dfe`**: bump `@aoctech/auth-client` to `^1.1.0`+ once
  published (currently pinned `^1.0.0`), or leave a note explaining why not.

## Testing

All new tests run via the existing `npm test` (`tsc` then `node --test` against compiled
`dist/`) — no new test framework, no new dependency. `BroadcastChannel` tests (R2/R3) need
a test double since two `OAuthClient` instances in one Node process share no real browser
messaging — a same-process in-memory pub/sub stub keyed by channel name is enough (~10
lines), not a real `BroadcastChannel` polyfill dependency.

## Rollout

Ship R1, R4–R10 together as `1.1.0` (backwards compatible: `IdTokenClaims` stays exported).
R2/R3 (`BroadcastChannel` coordination) can ship in the same release since they're additive
and feature-detected — no config flag needed, no consumer changes required to adopt it.
