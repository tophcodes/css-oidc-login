import { DataFactory } from 'n3';
import {
  getLoggerFor, HttpError, InternalServerError, RepresentationMetadata,
} from '@solid/community-server';

const { namedNode } = DataFactory;

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
 * The map is bounded. Nothing authenticates the route that fills it, so the
 * number of logins in progress is whatever anyone cares to ask for, and an
 * entry that is never redeemed is otherwise only noticed when somebody asks
 * for that exact state again — which an abandoned one never is. See
 * {@link reclaim}.
 *
 * A bound that is reached has to be paid for by somebody, and the one thing it
 * may not cost is a login that is already in progress: whoever fills the store
 * is unauthenticated, so evicting to make room hands that same unauthenticated
 * party the power to throw a user out of their login — the very thing the
 * bound was added to prevent being possible at all. So a full store refuses
 * the new login instead. See {@link create}.
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
   * The most logins that may be in progress at once. Reached only by someone
   * asking for more than a server's worth of logins within one TTL, and past
   * it further logins are refused rather than the process growing without end.
   */
  public readonly maxPending: number;

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

  /**
   * Predicate carrying the `Retry-After` value of a refusal. A deployment maps
   * this IRI to the `Retry-After` header in the server's header-mapping
   * writer, the same way it maps {@link setCookiePredicate}. Unmapped, a
   * caller meeting a full store is told to come back later without being told
   * when, which costs them a wait and nobody anything else.
   */
  public readonly retryAfterPredicate = 'urn:css-oidc-login:http:retryAfter';

  private readonly logger = getLoggerFor(this);

  public constructor(ttlMs = 600000, cookieName = 'css-oidc-login-pending', maxPending = 10000) {
    this.ttlMs = ttlMs;
    this.cookieName = cookieName.startsWith(HOST_PREFIX) ? cookieName : `${HOST_PREFIX}${cookieName}`;
    this.maxPending = maxPending;
  }

  /**
   * Takes a login into the store, or refuses it because there is no room.
   *
   * Expired logins are what makes room. Once none are left, the login being
   * started is the one that gives way, because it is the only one that has
   * nothing to lose: it has not left for the provider yet, and the person
   * starting it learns immediately that they should try again. Every other
   * choice spends somebody else's login in progress on it — an eviction of any
   * kind, however it picks its victim, lets whoever fills the store decide who
   * gets thrown out, and filling it takes nothing but unauthenticated
   * requests. What this costs is that a store held full stops new logins from
   * starting; what it buys is that no login that has already begun can be
   * taken away by anyone but its owner.
   */
  public async create(state: string, data: PendingLogin): Promise<void> {
    this.reclaim();
    // Room a state already holds is room it keeps: the cap decides what may
    // come into the store, and a state already in it is not coming in. Every
    // login is written under a state generated for it alone, so a state
    // written twice is one login being renewed rather than one login naming
    // another's, and a renewal takes no room that the login was not already
    // occupying. Asked before the entry is taken out, because from there on
    // there is nothing left to keep and a refusal would drop the very login it
    // was about to renew.
    if (!this.pending.has(state) && this.pending.size >= this.maxPending) {
      // How full the store is, and therefore what a flood costs and when the
      // next one lands, is measurable by anyone who is told the number, and
      // nothing authenticates the route that fills it. The operator is the one
      // who can act on it.
      this.logger.warn(`Refusing a login: ${this.maxPending} logins are already in progress.`);
      throw this.outOfRoom();
    }
    // A state already in the store gets a later expiry, so it has to leave its
    // place rather than keep it: {@link reclaim} stops at the first entry that
    // is still live, which reclaims everything expired only while the order
    // entries sit in is the order they expire in. Taking it out and putting it
    // back is what holds the two in the same order by construction rather than
    // by nobody ever asking twice.
    this.pending.delete(state);
    this.pending.set(state, { data, expires: Date.now() + this.ttlMs });
  }

  /**
   * A store with no room left is a server that is momentarily out of a
   * resource, not a caller who asked for something wrong: the request that
   * meets a full store is the same request that would have been accepted a
   * moment earlier and will be again once the logins in progress finish or
   * expire. So it is refused as a condition of this server that passes, with
   * the status that says exactly that — and, because it passes on its own, with
   * how long it takes at the outside. Every entry is gone within one TTL of
   * being written, so that is the wait after which the store has room again
   * even if nobody completes a login and nobody else stops asking.
   */
  private outOfRoom(): HttpError {
    const metadata = new RepresentationMetadata();
    metadata.add(namedNode(this.retryAfterPredicate), `${Math.max(0, Math.ceil(this.ttlMs / 1000))}`);
    return new HttpError(
      503,
      'ServiceUnavailableHttpError',
      'This server cannot take another login right now. Try again in a few minutes.',
      { metadata },
    );
  }

  /**
   * Drops the logins that have expired, on the only occasion the store is
   * otherwise touched at all. Every entry gets the same lifetime, so a map
   * that keeps insertion order holds them in the order they expire: the front
   * is what expires first, and walking it stops at the first entry that is
   * still live, which is the usual case and costs nothing.
   *
   * Expiry is the only thing that takes an entry out from under its owner, and
   * an expired login is one nobody can complete any more.
   */
  private reclaim(): void {
    const now = Date.now();
    for (const [state, entry] of this.pending) {
      if (entry.expires >= now) {
        return;
      }
      this.pending.delete(state);
    }
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
    let url: URL;
    try {
      url = new URL(callbackUrl);
    } catch {
      throw new InternalServerError(
        `The configured callback URL ${callbackUrl} is not an absolute URL, so this server cannot ` +
        `write the pending-login cookie ${this.cookieName} for it.`,
      );
    }
    if (url.protocol !== 'https:') {
      throw new InternalServerError(
        `The pending-login cookie ${this.cookieName} is only stored by a browser over HTTPS, ` +
        `but the callback URL ${callbackUrl} is not. ` +
        'Serve this server over HTTPS; logging in through an external provider cannot be made ' +
        'safe over plain HTTP.',
      );
    }
  }
}
