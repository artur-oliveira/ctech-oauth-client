import { generatePKCE, generateState } from "./pkce.js";
import { NamespacedStorage } from "./storage.js";
import { decodeIdToken, type IdTokenClaims } from "./jwt.js";
import type { OAuthClientConfig, TokenResult } from "./types.js";

const AUTH_HINT_COOKIE = "ctech_auth";
const AUTH_STATE_ACTIVE = "active";
const AUTH_STATE_REVOKED = "revoked";

/**
 * Browser OAuth 2.0 + PKCE client for apps behind the ctech-account IdP.
 * One instance per app, configured with that app's client_id/redirect_uri/scope.
 */
export class OAuthClient {
  private readonly storage: NamespacedStorage;
  private inFlightRefresh: Promise<TokenResult | null> | null = null;

  constructor(private readonly config: OAuthClientConfig) {
    this.storage = new NamespacedStorage(config.storagePrefix ?? config.clientId);
  }

  /**
   * Reads the non-HttpOnly `ctech_auth` marker cookie the IdP sets on the
   * parent domain after any successful code exchange. Its absence is the
   * cheap, cross-subdomain signal that a refresh has no chance of succeeding
   * — checking it before calling /v1.0/token is what keeps a silent refresh
   * fired with no session (e.g. an SPA's first mount) from burning the
   * IdP's shared brute-force rate limit on a doomed request.
   */
  hasAuthHint(cookieString: string = typeof document !== "undefined" ? document.cookie : ""): boolean {
    return cookieString.split("; ").some((c) => c.startsWith(`${AUTH_HINT_COOKIE}=`));
  }

  /** Clears the hint cookie across every domain suffix, since the IdP set it
   * on the parent domain rather than this app's own host. */
  clearAuthHint(): void {
    if (typeof document === "undefined") return;
    const expired = `${AUTH_HINT_COOKIE}=; Max-Age=0; path=/`;
    document.cookie = expired;
    const parts = window.location.hostname.split(".");
    for (let i = 0; i < parts.length - 1; i++) {
      document.cookie = `${expired}; domain=.${parts.slice(i).join(".")}`;
    }
  }

  private isRevoked(): boolean {
    return this.storage.get("auth_state") === AUTH_STATE_REVOKED;
  }

  private setAuthState(state: typeof AUTH_STATE_ACTIVE | typeof AUTH_STATE_REVOKED): void {
    this.storage.set("auth_state", state);
  }

  /** Redirects to /v1.0/authorize, stashing PKCE verifier + state + returnTo
   * in sessionStorage for exchangeCode() to pick up after the callback. */
  async startOAuthFlow(returnTo = "/"): Promise<void> {
    const state = generateState();
    const { codeVerifier, codeChallenge } = await generatePKCE();

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

    window.location.href = `${this.config.baseUrl}/v1.0/authorize?${params}`;
  }

  /** Exchanges an authorization_code for tokens. Throws on state mismatch or
   * a non-2xx response — callers decide how to surface that. */
  async exchangeCode(code: string, state: string): Promise<TokenResult & { returnTo: string }> {
    const storedState = this.storage.get("oauth_state");
    if (!storedState || storedState !== state) {
      throw new Error("OAuth state mismatch");
    }
    const verifier = this.storage.get("oauth_verifier") ?? "";
    const returnTo = this.storage.get("oauth_return_to") ?? "/";
    this.storage.remove("oauth_state");
    this.storage.remove("oauth_verifier");
    this.storage.remove("oauth_return_to");

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
    });

    const res = await fetch(`${this.config.baseUrl}/v1.0/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      credentials: "include",
      body: body.toString(),
    });
    if (!res.ok) {
      throw new Error(`Token exchange failed (${res.status}): ${await res.text()}`);
    }
    const data = await res.json();
    this.setAuthState(AUTH_STATE_ACTIVE);
    return { accessToken: data.access_token, idToken: data.id_token ?? null, returnTo };
  }

  /**
   * Guarded, single-flight silent refresh. Returns null (never throws) when
   * a refresh isn't worth attempting or fails — callers fall back to
   * startOAuthFlow(). Safe to call from multiple places at once (app boot,
   * a 401 retry interceptor) without firing duplicate /v1.0/token requests.
   */
  async refresh(): Promise<TokenResult | null> {
    if (this.isRevoked()) return null;
    if (!this.hasAuthHint()) return null;
    if (this.inFlightRefresh) return this.inFlightRefresh;

    this.inFlightRefresh = this.doRefresh().finally(() => {
      this.inFlightRefresh = null;
    });
    return this.inFlightRefresh;
  }

  private async doRefresh(): Promise<TokenResult | null> {
    try {
      const body = new URLSearchParams({ grant_type: "refresh_token", client_id: this.config.clientId });
      const res = await fetch(`${this.config.baseUrl}/v1.0/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        credentials: "include",
        body: body.toString(),
      });
      if (!res.ok) {
        this.setAuthState(AUTH_STATE_REVOKED);
        return null;
      }
      const data = await res.json();
      this.setAuthState(AUTH_STATE_ACTIVE);
      return { accessToken: data.access_token, idToken: data.id_token ?? null };
    } catch {
      // Network error — transient, not a revocation. Leave auth_state as-is
      // so the next attempt (e.g. the user's next navigation) tries again.
      return null;
    }
  }

  /** Best-effort server-side token revocation. Marks locally revoked first,
   * so a refresh racing this call never resurrects the session. */
  async revoke(): Promise<void> {
    this.setAuthState(AUTH_STATE_REVOKED);
    try {
      await fetch(`${this.config.baseUrl}/v1.0/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        credentials: "include",
      });
    } catch {
      // Best-effort — the local revoke already stops future refreshes.
    }
  }

  /** RP-initiated logout — ends the IdP SSO session (ctech_session cookie),
   * not just this app's tokens. Call revoke() first if this app also holds
   * a per-client refresh token that should die immediately. */
  endSessionRedirect(returnTo = "/login"): void {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      post_logout_redirect_uri: `${window.location.origin}${returnTo}`,
    });
    window.location.href = `${this.config.baseUrl}/v1.0/auth/end-session?${params}`;
  }

  decodeIdToken(idToken: string): IdTokenClaims | null {
    return decodeIdToken(idToken);
  }
}
