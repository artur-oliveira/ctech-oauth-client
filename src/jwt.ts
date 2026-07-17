export interface IdTokenClaims {
  username?: string;
  first_name?: string;
  last_name?: string;
}

/** Decodes an id_token payload client-side (no signature check — the token
 * came straight from the IdP over TLS at exchange time, this is for display
 * only). Resource-server access tokens are audience-restricted and can't
 * carry these name claims, so consumers read them from the id_token instead. */
export function decodeIdToken(idToken: string): IdTokenClaims | null {
  try {
    const payload = idToken.split(".")[1];
    if (!payload) return null;
    let b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);
    const json = decodeURIComponent(
      Array.from(atob(b64), (c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join(""),
    );
    const claims = JSON.parse(json) as Record<string, unknown>;
    const firstName = typeof claims.given_name === "string" ? claims.given_name : undefined;
    const lastName = typeof claims.family_name === "string" ? claims.family_name : undefined;
    const username = typeof claims.preferred_username === "string" ? claims.preferred_username : undefined;
    if (!firstName && !lastName && !username) return null;
    return { username, first_name: firstName, last_name: lastName };
  } catch {
    return null;
  }
}
