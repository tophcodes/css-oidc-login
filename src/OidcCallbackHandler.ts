import { timingSafeEqual } from 'node:crypto';
import { DataFactory, Parser, Store } from 'n3';
import type { Term } from 'n3';
import {
  ResolveLoginHandler, BadRequestHttpError, HttpError, RepresentationMetadata,
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
   * Predicate a profile uses to attach a grant to its WebID. Defaults to
   * {@link DEFAULT_TRUST_PREDICATE}. Never set this to `solid:oidcIssuer`.
   */
  trustPredicate?: string;
}

/**
 * A token exchange that never gets an answer out of the provider went wrong
 * somewhere the caller has no part in: the endpoint is the one discovery
 * named, and the request carries this server's own credentials. Reporting that
 * as a bad request blames a browser for a host being down, and buries the one
 * failure an operator can act on among the many that are genuinely the
 * caller's. So it is reported as the provider's — 502 for a provider that
 * answered in a way that is no answer at all, and 504 for one that did not
 * answer inside the deadline, which is the case an operator can tell apart at
 * a glance. What the provider does say about the code, verifier and redirect
 * URI presented to it stays a 400: that is a verdict on the callback this
 * caller brought.
 */
const providerFailed = (message: string): HttpError => new HttpError(502, 'BadGatewayHttpError', message);
const providerTimedOut = (message: string): HttpError => new HttpError(504, 'GatewayTimeoutHttpError', message);

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

  public constructor(args: OidcCallbackHandlerArgs) {
    super(args.accountStore, args.cookieStore);
    this.args = args;
  }

  public async login(
    { method, json, metadata, target }: JsonInteractionHandlerInput,
  ): Promise<JsonRepresentation<LoginOutputType>> {
    assertPostOnly(method);

    const { state, code } = json as { state?: string; code?: string };
    if (!state) {
      throw new BadRequestHttpError('Callback carried no state.');
    }
    if (!code) {
      throw new BadRequestHttpError('Callback carried no code.');
    }

    // The cookie is the browser's half of the login, and the half an attacker
    // holding a state and a code does not have.
    const { store } = this.args;
    const handle = metadata.get(namedNode(store.cookiePredicate))?.value;
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
    if (typeof webId !== 'string') {
      throw new BadRequestHttpError(`The provider returned no webid claim (${claimName}) for this user.`);
    }
    const subject = claims.sub;
    if (typeof subject !== 'string' || subject.length === 0) {
      throw new BadRequestHttpError('ID token carried no subject.');
    }

    const links = await this.args.storage.find(WEBID_STORAGE_TYPE, { webId });
    if (links.length === 0) {
      throw new BadRequestHttpError(`WebID ${webId} is not linked to an account on this server.`);
    }
    // Which of several accounts was meant is not knowable here, and the order
    // the storage returns them in is not defined, so picking one would be a
    // guess about who is logging in.
    if (links.length > 1) {
      throw new BadRequestHttpError(
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
        throw providerTimedOut(`The token endpoint did not answer within ${RESPONSE_TIMEOUT_MS}ms.`);
      }
      throw providerFailed('The token endpoint could not be reached.');
    }
    if (response.status >= 300 && response.status < 400) {
      throw providerFailed(
        'The token endpoint redirects elsewhere; the exchange has to happen at the endpoint discovery named.',
      );
    }
    if (!response.ok) {
      throw await this.describeExchangeRefusal(response);
    }

    const body = this.parseTokenResponse(await this.readTokenBody(response));
    if (typeof body.id_token !== 'string' || body.id_token.length === 0) {
      throw providerFailed('The token response carried no ID token.');
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
        (): Error => providerFailed(`The token response is larger than ${RESPONSE_MAX_BYTES} bytes.`),
      );
    } catch (error) {
      if (HttpError.isInstance(error)) {
        throw error;
      }
      const name = (error as { name?: string }).name;
      if (name === 'TimeoutError' || name === 'AbortError') {
        throw providerTimedOut(`The token endpoint did not answer within ${RESPONSE_TIMEOUT_MS}ms.`);
      }
      throw providerFailed('The token response could not be read.');
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
    return providerFailed(
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
        throw providerTimedOut(`The token endpoint did not answer within ${RESPONSE_TIMEOUT_MS}ms.`);
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
      throw providerFailed('The token response is not valid JSON.');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw providerFailed('The token response is not a JSON object.');
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
      throw providerFailed('The ID token is not a well-formed JWT.');
    }

    let payload: unknown;
    try {
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch {
      throw providerFailed('The ID token payload is not valid JSON.');
    }
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
      throw providerFailed('The ID token payload is not a JSON object.');
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
   */
  private assertIssuedForUs(claims: Record<string, unknown>): void {
    const expectedIssuer = withoutTrailingSlashes(this.args.issuer);
    if (typeof claims.iss !== 'string') {
      throw new BadRequestHttpError('ID token carried no issuer.');
    }
    const actualIssuer = withoutTrailingSlashes(claims.iss);
    if (actualIssuer !== expectedIssuer) {
      throw new BadRequestHttpError(`ID token was issued by ${claims.iss}, not by ${expectedIssuer}.`);
    }

    if (claims.aud === undefined || claims.aud === null) {
      throw new BadRequestHttpError('ID token carried no audience.');
    }
    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audience.includes(this.args.clientId)) {
      throw new BadRequestHttpError('ID token was issued for a different client.');
    }
    const azpPresent = 'azp' in claims && claims.azp !== undefined;
    if (azpPresent && claims.azp !== this.args.clientId) {
      throw new BadRequestHttpError('ID token names another client as the authorized party.');
    }
    if (!azpPresent && audience.length > 1) {
      throw new BadRequestHttpError(
        'ID token names several audiences without naming this client as the authorized party.',
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
      throw new BadRequestHttpError(`The profile at ${webId} could not be parsed as ${PROFILE_MEDIA_TYPE}.`);
    }

    const store = new Store(quads);
    const expected = withoutTrailingSlashes(this.args.issuer);

    const grants = store.getObjects(namedNode(webId), namedNode(predicate), defaultGraph())
      .filter((term): boolean => isNode(term))
      .filter((grant): boolean => store.getObjects(grant, namedNode(GRANT_ISSUER_PREDICATE), defaultGraph())
        .some((term): boolean =>
          term.termType === 'NamedNode' && withoutTrailingSlashes(term.value) === expected));

    if (grants.length === 0) {
      throw new BadRequestHttpError(
        `The profile at ${webId} does not accept authentication from ${expected}.`,
      );
    }

    // The subject is an opaque string the provider assigns, so it is compared
    // verbatim and only as a literal: an IRI would be a different claim.
    const bound = grants.some((grant): boolean =>
      store.getObjects(grant, namedNode(GRANT_SUBJECT_PREDICATE), defaultGraph())
        .some((term): boolean => term.termType === 'Literal' && term.value === subject));

    if (!bound) {
      throw new BadRequestHttpError(
        `The profile at ${webId} does not accept ${subject} as its subject at ${expected}.`,
      );
    }
  }

  /**
   * Reads a profile document, refusing anything that is not plain Turtle served
   * from the WebID's own URL, and giving up rather than waiting or reading
   * without end.
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
      throw new BadRequestHttpError(this.describeProfileFailure(webId, error));
    }

    if (response.status >= 300 && response.status < 400) {
      throw new BadRequestHttpError(
        `The profile at ${webId} redirects elsewhere; it has to be served from the WebID's own URL.`,
      );
    }
    if (!response.ok) {
      throw new BadRequestHttpError(`Could not read the profile at ${webId} (${response.status}).`);
    }

    const mediaType = (response.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
    if (mediaType !== PROFILE_MEDIA_TYPE) {
      throw new BadRequestHttpError(
        `The profile at ${webId} was served as ${mediaType || 'no media type'}, not as ${PROFILE_MEDIA_TYPE}.`,
      );
    }

    return this.readCapped(webId, response);
  }

  /** Reads the profile body, refusing one that never stops arriving. */
  private async readCapped(webId: string, response: Response): Promise<string> {
    try {
      return await readCapped(
        response,
        (): Error =>
          new BadRequestHttpError(`The profile at ${webId} is larger than ${RESPONSE_MAX_BYTES} bytes.`),
      );
    } catch (error) {
      if (BadRequestHttpError.isInstance(error)) {
        throw error;
      }
      throw new BadRequestHttpError(this.describeProfileFailure(webId, error));
    }
  }

  private describeProfileFailure(webId: string, error: unknown): string {
    const name = (error as { name?: string }).name;
    if (name === 'TimeoutError' || name === 'AbortError') {
      return `The profile at ${webId} did not answer within ${RESPONSE_TIMEOUT_MS}ms.`;
    }
    return `Could not read the profile at ${webId}.`;
  }
}
