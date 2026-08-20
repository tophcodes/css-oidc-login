import { InternalServerError } from '@solid/community-server';

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
 * Prefix a browser only accepts on a cookie that is `Secure`, has `Path=/` and
 * names no `Domain`. Those three together are what stop a sibling host from
 * writing this cookie; see {@link PendingLoginStore.cookie}.
 */
const HOST_PREFIX = '__Host-';

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
 *
 * One browser can carry one login in progress. A second login started in the
 * same browser overwrites the first one's cookie, after which the first can no
 * longer be completed — it is left to expire rather than being spent. Holding
 * several would mean several cookies, and a cookie per login is a name per
 * login, which the `__Host-` prefix and the fixed name of the parser mapping
 * both rule out.
 */
export class PendingLoginStore {
  private readonly pending = new Map<string, { data: PendingLogin; expires: number }>();

  /** How long a login in progress stays redeemable; also the cookie's lifetime. */
  public readonly ttlMs: number;
  /**
   * Name of the cookie holding the handle, always carrying the `__Host-`
   * prefix. It is both the name written and the name a deployment maps in the
   * server's cookie parser, so the two cannot drift apart.
   */
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
    this.cookieName = cookieName.startsWith(HOST_PREFIX) ? cookieName : `${HOST_PREFIX}${cookieName}`;
  }

  public async create(state: string, data: PendingLogin): Promise<void> {
    this.pending.set(state, { data, expires: Date.now() + this.ttlMs });
  }

  /**
   * The login this state belongs to, without spending it. The caller checks
   * the handle against it first, so that a caller who cannot produce the
   * matching handle leaves somebody else's login in progress untouched.
   */
  public async peek(state: string): Promise<PendingLogin | undefined> {
    const entry = this.pending.get(state);
    if (!entry) {
      return undefined;
    }
    if (entry.expires < Date.now()) {
      this.pending.delete(state);
      return undefined;
    }
    return entry.data;
  }

  public async consume(state: string): Promise<PendingLogin | undefined> {
    const data = await this.peek(state);
    this.pending.delete(state);
    return data;
  }

  /**
   * The `Set-Cookie` value handing a handle to the browser.
   *
   * `HttpOnly` because no page has any use for the handle, and
   * `SameSite=Strict` because a cookie that a cross-site form submission
   * carries would bind that submission just as happily as a real login.
   *
   * The `__Host-` prefix is what keeps the cookie on this exact host. Without
   * it, any host that shares a registrable domain — every pod on a server that
   * gives each pod a subdomain — can write a cookie of the same name for
   * `Domain=.example.com`, and that cookie is sent on a same-site request to
   * the callback. The victim's browser would then present the attacker's
   * handle alongside the attacker's own state and code, and the check this
   * cookie exists for would pass. The prefix costs the `Path` scoping: a
   * browser only stores such a cookie for `Path=/`, so it travels with every
   * request to this host rather than only with the callback.
   */
  public cookie(handle: string, callbackUrl: string): string {
    return this.serialize(handle, callbackUrl, Math.ceil(this.ttlMs / 1000));
  }

  /** The `Set-Cookie` value taking a spent handle back off the browser. */
  public expiredCookie(callbackUrl: string): string {
    return this.serialize('', callbackUrl, 0);
  }

  private serialize(value: string, callbackUrl: string, maxAgeSeconds: number): string {
    this.assertSecureCallback(callbackUrl);
    return `${this.cookieName}=${value}; Path=/; Max-Age=${maxAgeSeconds}; Secure; HttpOnly; SameSite=Strict`;
  }

  /**
   * A `__Host-` cookie is only stored over HTTPS, so a server reachable over
   * plain HTTP cannot hold a pending login at all and every login would fail
   * at the callback with a missing cookie. That failure is turned into this
   * one, which happens at the first login attempt and names its cause, because
   * an operator reading "no cookie" would sooner conclude the package is
   * broken than that their deployment is.
   */
  private assertSecureCallback(callbackUrl: string): void {
    if (new URL(callbackUrl).protocol !== 'https:') {
      throw new InternalServerError(
        `The pending-login cookie ${this.cookieName} is only stored by a browser over HTTPS, ` +
        `but the callback URL ${callbackUrl} is not. ` +
        'Serve this server over HTTPS; logging in through an external provider cannot be made ' +
        'safe over plain HTTP.',
      );
    }
  }
}
