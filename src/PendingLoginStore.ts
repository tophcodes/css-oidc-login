export interface PendingLogin {
  codeVerifier: string;
  /**
   * Opaque handle also written to the browser as a cookie. The callback is
   * only answered when the browser returns this exact value, which is what
   * makes a login belong to one browser rather than to whoever holds the state.
   */
  handle: string;
}

/**
 * Holds the logins that are in progress, and owns the cookie that binds each of
 * them to the browser that started it.
 *
 * The cookie lives here rather than in either handler because both handlers
 * have to agree on its name to the letter, and one shared instance is what the
 * configuration already gives them.
 *
 * The server has no generic "set this cookie" hook: its own account cookie is
 * carried through response metadata and turned into a header by a writer that
 * is wired in configuration. So this class supplies the two halves the same
 * mechanism needs — the predicate an incoming handle is read from, and the
 * predicate a complete `Set-Cookie` value is written to. The value is
 * serialised here instead of being handed to the server's own cookie writer
 * because that writer fixes `SameSite=Lax`, and `Strict` is the property this
 * cookie exists for.
 */
export class PendingLoginStore {
  private readonly pending = new Map<string, { data: PendingLogin; expires: number }>();

  /** How long a login in progress stays redeemable; also the cookie's lifetime. */
  public readonly ttlMs: number;
  /** Name of the cookie holding the handle. */
  public readonly cookieName: string;

  /**
   * Predicate the handle sent by the browser is read from. A deployment maps
   * {@link cookieName} to this IRI in the server's cookie parser.
   */
  public readonly cookiePredicate = 'urn:css-oidc-login:http:pendingLoginCookie';

  /**
   * Predicate carrying a complete `Set-Cookie` value. A deployment maps this
   * IRI to the `Set-Cookie` header in the server's header-mapping writer.
   */
  public readonly setCookiePredicate = 'urn:css-oidc-login:http:setPendingLoginCookie';

  public constructor(ttlMs = 600000, cookieName = 'css-oidc-login-pending') {
    this.ttlMs = ttlMs;
    this.cookieName = cookieName;
  }

  public async create(state: string, data: PendingLogin): Promise<void> {
    this.pending.set(state, { data, expires: Date.now() + this.ttlMs });
  }

  public async consume(state: string): Promise<PendingLogin | undefined> {
    const entry = this.pending.get(state);
    this.pending.delete(state);
    if (!entry || entry.expires < Date.now()) {
      return undefined;
    }
    return entry.data;
  }

  /**
   * The `Set-Cookie` value handing a handle to the browser, scoped to the
   * callback route and to nothing else.
   *
   * `HttpOnly` because no page has any use for the handle, and
   * `SameSite=Strict` because a cookie that a cross-site form submission
   * carries would bind that submission just as happily as a real login.
   * `Secure` is left off to match the server's own account cookie, which omits
   * it so that `http://localhost` deployments keep working.
   */
  public cookie(handle: string, callbackUrl: string): string {
    return this.serialize(handle, callbackUrl, Math.ceil(this.ttlMs / 1000));
  }

  /** The `Set-Cookie` value taking a spent handle back off the browser. */
  public expiredCookie(callbackUrl: string): string {
    return this.serialize('', callbackUrl, 0);
  }

  private serialize(value: string, callbackUrl: string, maxAgeSeconds: number): string {
    const path = new URL(callbackUrl).pathname;
    return `${this.cookieName}=${value}; Path=${path}; Max-Age=${maxAgeSeconds}; HttpOnly; SameSite=Strict`;
  }
}
