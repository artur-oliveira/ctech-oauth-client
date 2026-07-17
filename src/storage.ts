/** sessionStorage wrapper namespaced by client, so two OAuthClient instances
 * (e.g. two apps sharing a domain) never collide on the same key. */
export class NamespacedStorage {
  constructor(private readonly prefix: string) {}

  private key(name: string): string {
    return `${this.prefix}:${name}`;
  }

  get(name: string): string | null {
    try {
      return sessionStorage.getItem(this.key(name));
    } catch {
      return null;
    }
  }

  set(name: string, value: string): void {
    try {
      sessionStorage.setItem(this.key(name), value);
    } catch {
      // Private-mode storage rejection or SSR — non-fatal, flow just won't persist.
    }
  }

  remove(name: string): void {
    try {
      sessionStorage.removeItem(this.key(name));
    } catch {
      // Ignore.
    }
  }
}
