function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function randomBytes(length: number): Uint8Array {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

/** RFC 7636 PKCE pair — S256 challenge derived from a 32-byte random verifier. */
export async function generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const codeVerifier = toBase64Url(randomBytes(32));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const codeChallenge = toBase64Url(new Uint8Array(digest));
  return { codeVerifier, codeChallenge };
}

/** Opaque per-flow CSRF token for the `state` param — 32 hex chars. */
export function generateState(): string {
  return Array.from(randomBytes(16), (b) => b.toString(16).padStart(2, "0")).join("");
}
