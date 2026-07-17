export interface OAuthClientConfig {
  /** ctech-account API base URL, e.g. https://accountsapi.aoctech.app */
  baseUrl: string;
  /** OAuth client_id registered for this app. */
  clientId: string;
  /** Must exactly match a redirect_uri registered for clientId. */
  redirectUri: string;
  /** Space-separated scope string requested at /v1.0/authorize. */
  scope: string;
  /** sessionStorage key namespace. Defaults to clientId. */
  storagePrefix?: string;
}

export interface TokenResult {
  accessToken: string;
  idToken?: string | null;
}
