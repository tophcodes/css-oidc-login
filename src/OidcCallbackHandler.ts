import { timingSafeEqual } from 'node:crypto';
import { DataFactory, Parser, Store } from 'n3';
import type { Term } from 'n3';
import {
  ResolveLoginHandler, BadRequestHttpError, ConflictHttpError, ForbiddenHttpError, HttpError,
  InternalServerError, RepresentationMetadata,
} from '@solid/community-server';
import type {
  AccountStore, CookieStore, JsonInteractionHandlerInput,
  JsonRepresentation, LoginOutputType,
} from '@solid/community-server';
import { readCapped, RESPONSE_MAX_BYTES, RESPONSE_TIMEOUT_MS } from './limits.ts';
import { assertPostOnly } from './methods.ts';
import type { OidcDiscovery } from './OidcDiscovery.js';
import type { PendingLoginStore } from './PendingLoginStore.js';

const { namedNode, defaultGraph } = DataFactory;

/** Issuer identifiers are compared without their trailing slashes. */
const withoutTrailingSlashes = (iri: string): string => iri.replace(/\/*$/u, '');

/** Defined by the server's BaseWebIdStore, which also indexes `webId`. */
const WEBID_STORAGE_TYPE = 'webIdLink';

/** The only serialisation a profile is read as; anything else is refused. */
const PROFILE_MEDIA_TYPE = 'text/turtle';

/**
 * Predicate a profile uses to attach a grant to its WebID. Its own term
 * because no existing one carries this meaning — see `assertProfileGrantsLogin`.
 */
export const DEFAULT_TRUST_PREDICATE = 'https://tophcodes.github.io/css-oidc-login/ns#externalLogin';

/** Predicates read on the grant itself. Fixed, unlike the predicate carrying it. */
export const GRANT_ISSUER_PREDICATE = 'https://tophcodes.github.io/css-oidc-login/ns#issuer';
export const GRANT_SUBJECT_PREDICATE = 'https://tophcodes.github.io/css-oidc-login/ns#subject';

/**
 * What a configured predicate has to look like to be a predicate at all: a
 * scheme, and after it only characters an IRI may carry in a Turtle document —
 * anything except the space, the control characters, the backtick, and the
 * delimiters `<>"{}|^` and the backslash.
 *
 * Nothing narrower than that. The predicate is compared as a string against
 * what a profile carries and is never dereferenced, so a term of a
 * deployment's own vocabulary is as usable here under any scheme as an
 * `https:` one, and asking more of it would refuse terms that work.
 *
 * What this refuses is a value no parsed document can ever yield a predicate
 * for — a relative IRI, an empty string, one carrying a space or a delimiter.
 * Such a value matches every profile alike: not at all.
 */
const USABLE_PREDICATE = /^[A-Za-z][A-Za-z0-9+\-.]*:[^\u0000-\u0020<>"{}|^\\`]*$/u;

export interface WebIdLinkStorage {
  find: (type: string, query: { webId: string }) => Promise<{ accountId: string }[]>;
}

export interface OidcCallbackHandlerArgs {
  accountStore: AccountStore;
  cookieStore: CookieStore;
  store: PendingLoginStore;
  storage: WebIdLinkStorage;
  discovery: OidcDiscovery;
  /** Issuer identifier, matched against the token's `iss` claim. */
  issuer: string;
  clientId: string;
  clientSecret: string;
  callbackUrl: string;
  /** Claim holding the user's WebID. Defaults to `webid` (Solid-OIDC). */
  webIdClaim?: string;
  /**
   * Predicate a profile uses to attach a grant to its WebID. An absolute IRI,
   * under whatever scheme; defaults to {@link DEFAULT_TRUST_PREDICATE}. Never
   * set this to `solid:oidcIssuer`.
   */
  trustPredicate?: string;
}

/**
 * Two hosts answer to this handler, and the caller is neither of them: the
 * provider, at the endpoint its own discovery document named and with this
 * server's credentials in the request, and the host serving the profile that
 * the WebID in the provider's token resolves to. Neither is anything a browser
 * chose, so a failure at either is reported as the upstream failure it is —
 * 502 for a host that answered in a way that is no answer at all, and 504 for
 * one that did not answer inside the deadline, which is the case an operator
 * can tell apart at a glance. Reporting either as a bad request blames a
 * browser for somebody else's host, and buries the one failure an operator can
 * act on among the many that are genuinely the caller's.
 *
 * What the provider says about the code, verifier and redirect URI presented
 * to it stays a 400: that is a verdict on the callback this caller brought.
 * What the profile says about who may log in is neither — see
 * {@link loginRefused}.
 */
const upstreamFailed = (message: string): HttpError => new HttpError(502, 'BadGatewayHttpError', message);
const upstreamTimedOut = (message: string): HttpError => new HttpError(504, 'GatewayTimeoutHttpError', message);

/**
 * A login that nothing upstream failed on and this server still will not
 * complete: the profile carries no grant for it, or no account here is linked
 * to the WebID. Nothing in the request is malformed and no host misbehaved —
 * what is missing is permission, which is what a 403 says and a 400 does not.
 * Whoever reads it is also the one who can grant it, by writing the grant into
 * the profile or by linking the WebID to an account here.
 */
const loginRefused = (message: string): HttpError => new ForbiddenHttpError(message);

/**
 * What a WebID claim has to look like before this server fetches it and
 * repeats it in a message: an absolute http(s) URL with nothing in it that a
 * log line would read as a line of its own. The claim is a string chosen at
 * the provider, and for a mapped attribute that is a string chosen by whoever
 * holds the account there — so a value outside this is refused rather than
 * passed on, the same way an error code outside its charset is.
 */
const isUsableWebId = (value: string): boolean => {
  if (/[\u0000-\u0020\u007F]/u.test(value)) {
    return false;
  }
  try {
    const { protocol } = new URL(value);
    return protocol === 'https:' || protocol === 'http:';
  } catch {
    return false;
  }
};

/**
 * The statuses RFC 6749 §5.2 uses for an answer that says something about the
 * exchange: 400, or 401 for a client whose authentication the provider
 * refused. Any other status is a provider failing rather than judging.
 */
const OAUTH_ERROR_STATUSES = new Set([ 400, 401 ]);

/**
 * The one error code of RFC 6749 §5.2 that is a verdict on what this caller
 * brought: an authorization code that was already spent, has expired, was
 * issued to somebody else, or does not match the verifier or the redirect URI
 * of this exchange. Every other code names this server's own credentials,
 * registration or request — `invalid_client` above all, which is what a wrong
 * client secret comes back as, and which no browser can do anything about.
 */
const CALLER_ERROR_CODE = 'invalid_grant';

/**
 * What an `error` has to look like to be read as a code at all: the charset
 * RFC 6749 §A.7 fixes for it — visible ASCII without the double quote and the
 * backslash — and a length no code the protocol defines comes near needing.
 * The member is a string the provider chooses that ends up in a message handed
 * back to whoever called and in a line this server logs, so a value outside
 * this is refused rather than trimmed to fit: a trimmed code is a different
 * code, and naming one the provider never sent is worse than naming none,
 * which the refusal already reads as an answer that states nothing.
 */
const OAUTH_ERROR_CODE = /^[\u0021\u0023-\u005B\u005D-\u007E]{1,64}$/u;

/** Compares two secrets without leaking where they first differ. */
const secretsMatch = (left: string, right: string): boolean => {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
};

const isNode = (term: Term): boolean => term.termType === 'NamedNode' || term.termType === 'BlankNode';

export class OidcCallbackHandler extends ResolveLoginHandler {
  private readonly args: OidcCallbackHandlerArgs;

  /**
   * The trust predicate is this deployment's setting, and nothing further down
   * is in a position to say so: n3 makes a named node out of any string at all,
   * so a value that could never appear as a predicate in a profile is refused
   * nowhere — it matches nothing in every profile, and each login then ends as
   * a 403 telling a person their profile does not grant what it plainly does.
   * The value arrives here, so it is judged here, and an operator meets their
   * own typo at startup instead of reading it as somebody else's missing
   * permission.
   */
  public constructor(args: OidcCallbackHandlerArgs) {
    super(args.accountStore, args.cookieStore);
    if (args.trustPredicate !== undefined && !USABLE_PREDICATE.test(args.trustPredicate)) {
      throw new InternalServerError(
        `The configured trust predicate ${args.trustPredicate} is not an absolute IRI, so no profile can ` +
        'carry a grant under it and every login would be refused as if its owner had granted nothing.',
      );
    }
    this.args = args;
  }

  public async login(
    { method, json, metadata, target }: JsonInteractionHandlerInput,
  ): Promise<JsonRepresentation<LoginOutputType>> {
    assertPostOnly(method);

    // The body and the cookie jar are the caller's own, and a browser can be
    // made to send any shape of either: a body that is not an object of two
    // strings, or a jar holding two cookies of the one name. Read without
    // being asked about, each leaves this handler as an exception of this
    // server's own — a fault reported for input somebody else chose.
    if (typeof json !== 'object' || json === null || Array.isArray(json)) {
      throw new BadRequestHttpError('Callback carried no parameters.');
    }
    const { state, code } = json as { state?: unknown; code?: unknown };
    if (typeof state !== 'string' || state.length === 0) {
      throw new BadRequestHttpError('Callback carried no state.');
    }
    if (typeof code !== 'string' || code.length === 0) {
      throw new BadRequestHttpError('Callback carried no code.');
    }

    // The cookie is the browser's half of the login, and the half an attacker
    // holding a state and a code does not have.
    const { store } = this.args;
    const handles = metadata.getAll(namedNode(store.cookiePredicate));
    // Which of several is the one this login was started with is not knowable
    // here, and trying each in turn would turn the check into a search that a
    // caller decides the length of.
    if (handles.length > 1) {
      throw new BadRequestHttpError(
        `Callback carried ${handles.length} ${store.cookieName} cookies; ` +
        'a browser holds one login in progress, so exactly one belongs to it.',
      );
    }
    const handle = handles[0]?.value;
    if (!handle) {
      throw new BadRequestHttpError(
        `Callback carried no ${store.cookieName} cookie, ` +
        'so it does not belong to a login this browser started.',
      );
    }

    // Read without spending. The state alone proves only that some browser
    // started this login, so spending it before the handle is checked would
    // let anyone holding a leaked state destroy a login in progress. Only the
    // browser that started it gets to spend it.
    const pending = await store.peek(state);
    if (!pending) {
      throw new BadRequestHttpError('Unknown or expired state.');
    }
    if (!secretsMatch(handle, pending.handle)) {
      throw new BadRequestHttpError('The pending-login cookie does not belong to this login.');
    }
    await store.consume(state);

    const claims = await this.exchange(code, pending.codeVerifier);
    const claimName = this.args.webIdClaim ?? 'webid';
    const webId = claims[claimName];
    // A token minted without the claim is the provider answering a request
    // this deployment composed: the scopes it asks for, or the claim mapping
    // its client is registered with at the provider, do not produce the claim.
    // The person at the browser has no part in either and nothing to do about
    // it, and told as their bad request it is also the failure an operator is
    // least likely to find, arriving among every genuinely bad callback the
    // route refuses all day.
    if (typeof webId !== 'string' || webId.length === 0) {
      throw upstreamFailed(
        `The ID token carries no webid claim (${claimName}). A provider emits it only for a client ` +
        'whose registered scopes and claim mapping ask for it.',
      );
    }
    if (!isUsableWebId(webId)) {
      throw upstreamFailed(
        `The ID token carries a webid claim (${claimName}) that is not an absolute http(s) URL, ` +
        'so it names no profile this server could read.',
      );
    }
    // OIDC Core 2 makes `sub` REQUIRED: a token without one is not a token the
    // provider was allowed to compose, whatever the request asked of it.
    const subject = claims.sub;
    if (typeof subject !== 'string' || subject.length === 0) {
      throw upstreamFailed(
        'The ID token carries no subject (sub), which every ID token is required to carry.',
      );
    }

    const links = await this.args.storage.find(WEBID_STORAGE_TYPE, { webId });
    if (links.length === 0) {
      throw loginRefused(
        `WebID ${webId} is not linked to an account on this server; ` +
        'link it to one before logging in with it.',
      );
    }
    // Which of several accounts was meant is not knowable here, and the order
    // the storage returns them in is not defined, so picking one would be a
    // guess about who is logging in. The ambiguity sits in this server's own
    // account data rather than in the request or at either host, so it is
    // answered as the conflict it is: the same login would be granted if that
    // data named one account.
    if (links.length > 1) {
      throw new ConflictHttpError(
        `WebID ${webId} is linked to ${links.length} accounts on this server; ` +
        'unlink it from all but one to log in with it.',
      );
    }

    await this.assertProfileGrantsLogin(webId, subject);

    this.logger.debug(`Logging in ${webId} through the external provider`);
    // The handle is spent; the browser has no further use for it.
    const responseMetadata = new RepresentationMetadata(target);
    responseMetadata.add(
      namedNode(store.setCookiePredicate),
      store.expiredCookie(this.args.callbackUrl),
    );
    // `remember` is deliberately absent: the server writes it as an account-wide
    // setting, so naming it here would re-decide it for every session that
    // account already has. Leaving it out keeps the account's own choice.
    return { json: { accountId: links[0].accountId }, metadata: responseMetadata };
  }

  protected async exchange(code: string, codeVerifier: string): Promise<Record<string, unknown>> {
    const { token } = await this.args.discovery.endpoints();
    // A 307 or 308 replays this POST — client secret, code and verifier
    // included — at whatever host the response names. Refused, not followed.
    let response: Response;
    try {
      response = await fetch(token, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        redirect: 'manual',
        signal: AbortSignal.timeout(RESPONSE_TIMEOUT_MS),
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: this.args.callbackUrl,
          client_id: this.args.clientId,
          client_secret: this.args.clientSecret,
          code_verifier: codeVerifier,
        }),
      });
    } catch (error) {
      const name = (error as { name?: string }).name;
      if (name === 'TimeoutError' || name === 'AbortError') {
        throw upstreamTimedOut(`The token endpoint did not answer within ${RESPONSE_TIMEOUT_MS}ms.`);
      }
      throw upstreamFailed('The token endpoint could not be reached.');
    }
    if (response.status >= 300 && response.status < 400) {
      throw upstreamFailed(
        'The token endpoint redirects elsewhere; the exchange has to happen at the endpoint discovery named.',
      );
    }
    if (!response.ok) {
      throw await this.describeExchangeRefusal(response);
    }

    const body = this.parseTokenResponse(await this.readTokenBody(response));
    if (typeof body.id_token !== 'string' || body.id_token.length === 0) {
      throw upstreamFailed('The token response carried no ID token.');
    }

    // The signature is not re-verified, which OIDC Core 3.1.3.7 permits: the
    // token arrives over TLS on a direct back-channel call to the endpoint the
    // provider's own discovery document names, and "the TLS server validation
    // MAY be used to validate the issuer in place of checking the token
    // signature". The same section still requires iss, aud and azp to be
    // checked, and those checks are not optional — see below.
    const claims = this.decodeClaims(body.id_token);

    this.assertIssuedForUs(claims);
    return claims;
  }

  /**
   * Reads the token response, mapping a read that gives up part-way. The
   * deadline covers the body as well as the headers, so a provider that
   * answers and then trickles trips it here rather than at the fetch, and the
   * exception that ends such a read is not an `HttpError` at all — left
   * unmapped it reaches the client as an internal fault of this server for
   * something that happened at the provider's end.
   */
  private async readTokenBody(response: Response): Promise<string> {
    try {
      return await readCapped(
        response,
        (): Error => upstreamFailed(`The token response is larger than ${RESPONSE_MAX_BYTES} bytes.`),
      );
    } catch (error) {
      if (HttpError.isInstance(error)) {
        throw error;
      }
      const name = (error as { name?: string }).name;
      if (name === 'TimeoutError' || name === 'AbortError') {
        throw upstreamTimedOut(`The token endpoint did not answer within ${RESPONSE_TIMEOUT_MS}ms.`);
      }
      throw upstreamFailed('The token response could not be read.');
    }
  }

  /**
   * Turns a refusal by the token endpoint into what the client is told.
   *
   * RFC 6749 §5.2 gives a provider one way of saying something about the
   * exchange: a 400 — or a 401 for a client it would not authenticate —
   * carrying a JSON object whose `error` member names what was wrong. Only
   * that answer is read as a verdict at all, and of the codes it may carry
   * only {@link CALLER_ERROR_CODE} is a verdict on the caller.
   *
   * A 400 or 401 without a well-formed error body is treated as the
   * provider's failure too. Such an answer carries the status the protocol
   * attaches meaning to but not the statement that gives it that meaning, so
   * there is nothing in it that says this caller's code was bad; reading it as
   * one would blame the person logging in for a provider that did not answer
   * in the protocol's terms — the same mistake as blaming them for a 500. The
   * cost is that a provider which refuses a spent code without an error body
   * has its refusals reported as its own; the alternative cost is a person
   * being told their login attempt was malformed when this server's client
   * secret is wrong, which they cannot act on and nobody else gets to see.
   */
  private async describeExchangeRefusal(response: Response): Promise<HttpError> {
    const { status } = response;
    const code = await this.readOauthErrorCode(response);
    if (code === CALLER_ERROR_CODE && OAUTH_ERROR_STATUSES.has(status)) {
      return new BadRequestHttpError(`Token exchange failed with ${status} (${code}).`);
    }
    return upstreamFailed(
      `The token endpoint refused the exchange with ${status}${code ? ` (${code})` : ''}.`,
    );
  }

  /**
   * The `error` member of an RFC 6749 §5.2 error response, if the answer
   * carries one. A body that does not arrive, that runs past the cap, or that
   * is not a JSON object naming a code is an answer that states nothing, which
   * is the same to the caller as no body at all — so none of that is reported
   * as anything of its own.
   *
   * A read the deadline ends is the one thing here that is not merely a
   * missing statement. A provider that refuses and then trickles holds a
   * worker exactly as long as one that never answers, and that wait is what
   * the deadline exists to end; swallowed here it would be reported as a
   * refusal the provider never finished making, and the status that says
   * "waited and got nothing" would be lost on the one path that can still
   * reach it.
   */
  private async readOauthErrorCode(response: Response): Promise<string | undefined> {
    let body: string;
    try {
      body = await readCapped(response, (): Error => new Error('The error body does not end.'));
    } catch (error) {
      const name = (error as { name?: string }).name;
      if (name === 'TimeoutError' || name === 'AbortError') {
        throw upstreamTimedOut(`The token endpoint did not answer within ${RESPONSE_TIMEOUT_MS}ms.`);
      }
      return undefined;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      return undefined;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return undefined;
    }
    const { error } = parsed as { error?: unknown };
    return typeof error === 'string' && OAUTH_ERROR_CODE.test(error) ? error : undefined;
  }

  /**
   * Reads the answer of a token endpoint that said the exchange succeeded.
   * Nothing in it is the caller's: the endpoint is the one discovery named,
   * the request carried this server's own credentials, and what came back is
   * the provider's own composition. So a body this server cannot make sense of
   * is reported the same way a body that never arrives is — as the provider's
   * failure, not as a verdict on the callback somebody brought.
   */
  private parseTokenResponse(body: string): { id_token?: unknown } {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw upstreamFailed('The token response is not valid JSON.');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw upstreamFailed('The token response is not a JSON object.');
    }
    return parsed as { id_token?: unknown };
  }

  /**
   * Reads the claim set out of a JWT without verifying its signature. The
   * token is what the provider put in its own answer, so a string that is not
   * a JWT carrying a JSON object payload is that answer being unreadable
   * rather than a bad callback: the caller brought a code, and what was minted
   * for it was not theirs to compose. What the claims then say is checked
   * separately.
   */
  private decodeClaims(idToken: string): Record<string, unknown> {
    const parts = idToken.split('.');
    if (parts.length !== 3 || parts[1].length === 0) {
      throw upstreamFailed('The ID token is not a well-formed JWT.');
    }

    let payload: unknown;
    try {
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch {
      throw upstreamFailed('The ID token payload is not valid JSON.');
    }
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
      throw upstreamFailed('The ID token payload is not a JSON object.');
    }
    return payload as Record<string, unknown>;
  }

  /**
   * Rejects a token that was not issued by the configured provider, or that
   * was issued to a different client of it. Without the audience check any
   * client registered at the same provider could mint a token this server
   * would accept.
   *
   * OIDC Core 3.1.3.7 asks two separate things of `azp`, and both are needed
   * here: a token that carries the claim at all has to name this client in it,
   * and a token naming several audiences has to carry it. Membership in `aud`
   * alone would let another client of the same provider mint a token for
   * itself that also lists this one, and checking `azp` only for several
   * audiences would let it mint one addressed solely to this client.
   *
   * Nothing a caller sends reaches any of these claims. They are the
   * provider's own composition, matched against this deployment's configured
   * issuer and client id, so every refusal here is the provider having minted
   * a token that is not this server's — or this server's own configuration
   * naming a provider or a client it was not registered as. Both are the
   * operator's to act on and neither is a bad request, so each names the
   * configured value it was measured against.
   */
  private assertIssuedForUs(claims: Record<string, unknown>): void {
    const expectedIssuer = withoutTrailingSlashes(this.args.issuer);
    if (typeof claims.iss !== 'string') {
      throw upstreamFailed('The ID token carries no issuer (iss).');
    }
    const actualIssuer = withoutTrailingSlashes(claims.iss);
    if (actualIssuer !== expectedIssuer) {
      throw upstreamFailed(
        `The ID token was issued by an issuer other than the configured ${expectedIssuer}.`,
      );
    }

    if (claims.aud === undefined || claims.aud === null) {
      throw upstreamFailed('The ID token carries no audience (aud).');
    }
    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audience.includes(this.args.clientId)) {
      throw upstreamFailed(
        `The ID token was issued for a different client than the configured ${this.args.clientId}.`,
      );
    }
    const azpPresent = 'azp' in claims && claims.azp !== undefined;
    if (azpPresent && claims.azp !== this.args.clientId) {
      throw upstreamFailed(
        `The ID token names another client than the configured ${this.args.clientId} ` +
        'as the authorized party (azp).',
      );
    }
    if (!azpPresent && audience.length > 1) {
      throw upstreamFailed(
        'The ID token names several audiences without naming an authorized party (azp).',
      );
    }
  }

  /**
   * The per-person opt-in. A provider vouching for a WebID is not enough — the
   * profile that WebID resolves to must carry a grant naming both the provider
   * and the account at that provider. Naming the provider alone would only say
   * "this provider may authenticate me", which anybody else with an account
   * there could then ride on by getting this WebID into their own token.
   *
   * The grant has to be one the profile's owner made: attached to a node in the
   * default graph of the document the WebID itself resolves to. A statement
   * parked in a named graph, or a document some redirect substituted, are
   * content that merely appears near the WebID, not that assertion.
   *
   * Deliberately not `solid:oidcIssuer`: that predicate means "this issuer
   * mints my Solid-OIDC access tokens", and a Solid client reading it would
   * try to obtain DPoP-bound tokens from a provider that issues none.
   */
  private async assertProfileGrantsLogin(webId: string, subject: string): Promise<void> {
    const predicate = this.args.trustPredicate ?? DEFAULT_TRUST_PREDICATE;
    const body = await this.fetchProfile(webId);

    let quads;
    try {
      quads = new Parser({ baseIRI: webId }).parse(body);
    } catch {
      throw upstreamFailed(`The profile at ${webId} could not be parsed as ${PROFILE_MEDIA_TYPE}.`);
    }

    const store = new Store(quads);
    const expected = withoutTrailingSlashes(this.args.issuer);

    const grants = store.getObjects(namedNode(webId), namedNode(predicate), defaultGraph())
      .filter((term): boolean => isNode(term))
      .filter((grant): boolean => store.getObjects(grant, namedNode(GRANT_ISSUER_PREDICATE), defaultGraph())
        .some((term): boolean =>
          term.termType === 'NamedNode' && withoutTrailingSlashes(term.value) === expected));

    if (grants.length === 0) {
      throw loginRefused(
        `The profile at ${webId} does not accept authentication from ${expected}; ` +
        'its owner has to state that it does before this login can be completed.',
      );
    }

    // The subject is an opaque string the provider assigns, so it is compared
    // verbatim and only as a literal: an IRI would be a different claim.
    const bound = grants.some((grant): boolean =>
      store.getObjects(grant, namedNode(GRANT_SUBJECT_PREDICATE), defaultGraph())
        .some((term): boolean => term.termType === 'Literal' && term.value === subject));

    if (!bound) {
      throw loginRefused(
        `The profile at ${webId} does not accept ${subject} as its subject at ${expected}; ` +
        'its owner has to name that subject in the grant before this login can be completed.',
      );
    }
  }

  /**
   * Reads a profile document, refusing anything that is not plain Turtle served
   * from the WebID's own URL, and giving up rather than waiting or reading
   * without end.
   *
   * The host this waits on is not the caller's either. The URL is derived from
   * a WebID this server was handed in the provider's token, so a host that is
   * down, that answers with a status, that serves another media type or that
   * redirects is a host failing, exactly as the token endpoint is when it does
   * the same. Reported as the caller's, an operator whose pods serve profiles
   * as JSON-LD, or whose profile host is unreachable from this server, sees
   * every login die as somebody's bad request. What the profile *says* is a
   * different matter — see {@link assertProfileGrantsLogin}.
   */
  private async fetchProfile(webId: string): Promise<string> {
    let response: Response;
    try {
      response = await fetch(webId, {
        headers: { accept: PROFILE_MEDIA_TYPE },
        redirect: 'manual',
        signal: AbortSignal.timeout(RESPONSE_TIMEOUT_MS),
      });
    } catch (error) {
      throw this.describeProfileFailure(webId, error);
    }

    if (response.status >= 300 && response.status < 400) {
      throw upstreamFailed(
        `The profile at ${webId} redirects elsewhere; it has to be served from the WebID's own URL.`,
      );
    }
    if (!response.ok) {
      throw upstreamFailed(`The host serving the profile at ${webId} answered with ${response.status}.`);
    }

    const mediaType = (response.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
    if (mediaType !== PROFILE_MEDIA_TYPE) {
      throw upstreamFailed(
        `The profile at ${webId} was served as ${mediaType || 'no media type'}, not as ${PROFILE_MEDIA_TYPE}.`,
      );
    }

    return this.readProfileBody(webId, response);
  }

  /**
   * Reads the profile body, refusing one that never stops arriving. The
   * deadline covers the body as well as the headers, so a host that answers
   * and then trickles trips it here rather than at the fetch, and what ends
   * such a read is not an `HttpError` at all — left unmapped it reaches the
   * client as an internal fault of this server for a wait on somebody else's
   * host.
   */
  private async readProfileBody(webId: string, response: Response): Promise<string> {
    try {
      return await readCapped(
        response,
        (): Error => upstreamFailed(`The profile at ${webId} is larger than ${RESPONSE_MAX_BYTES} bytes.`),
      );
    } catch (error) {
      if (HttpError.isInstance(error)) {
        throw error;
      }
      throw this.describeProfileFailure(webId, error);
    }
  }

  /**
   * A host that did not answer is told apart from one that answered badly, the
   * same way the token endpoint's two are: it is the one case an operator can
   * recognise without reading a log, and the one that says the wait was this
   * server's to end.
   */
  private describeProfileFailure(webId: string, error: unknown): HttpError {
    const name = (error as { name?: string }).name;
    if (name === 'TimeoutError' || name === 'AbortError') {
      return upstreamTimedOut(`The profile at ${webId} did not answer within ${RESPONSE_TIMEOUT_MS}ms.`);
    }
    return upstreamFailed(`The host serving the profile at ${webId} could not be reached.`);
  }
}
