import { timingSafeEqual } from 'node:crypto';
import { DataFactory, Parser, Store } from 'n3';
import type { Term } from 'n3';
import { ResolveLoginHandler, BadRequestHttpError, RepresentationMetadata } from '@solid/community-server';
import type {
  AccountStore, CookieStore, JsonInteractionHandlerInput,
  JsonRepresentation, LoginOutputType,
} from '@solid/community-server';
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
 * How long a profile has to answer, and how much of it is read. A WebID
 * profile is a handful of triples; both limits are orders of magnitude above
 * that and still bounded, so one unresponsive or endless host cannot occupy a
 * worker or its memory.
 */
const PROFILE_TIMEOUT_MS = 5000;
const PROFILE_MAX_BYTES = 1048576;

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
    { json, metadata, target }: JsonInteractionHandlerInput,
  ): Promise<JsonRepresentation<LoginOutputType>> {
    const { state, code } = json as { state?: string; code?: string };
    if (!state) {
      throw new BadRequestHttpError('Callback carried no state.');
    }
    if (!code) {
      throw new BadRequestHttpError('Callback carried no code.');
    }

    // Read before the state is spent: a caller that cannot produce the cookie
    // must not be able to burn somebody else's login in progress.
    const { store } = this.args;
    const handle = metadata.get(namedNode(store.cookiePredicate))?.value;
    if (!handle) {
      throw new BadRequestHttpError(
        `Callback carried no ${store.cookieName} cookie, ` +
        'so it does not belong to a login this browser started.',
      );
    }

    const pending = await store.consume(state);
    if (!pending) {
      throw new BadRequestHttpError('Unknown or expired state.');
    }
    // The state alone proves only that some browser started this login. Whoever
    // answers the callback has to be the browser that did.
    if (!secretsMatch(handle, pending.handle)) {
      throw new BadRequestHttpError('The pending-login cookie does not belong to this login.');
    }

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
    const response = await fetch(token, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      redirect: 'manual',
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.args.callbackUrl,
        client_id: this.args.clientId,
        client_secret: this.args.clientSecret,
        code_verifier: codeVerifier,
      }),
    });
    if (response.status >= 300 && response.status < 400) {
      throw new BadRequestHttpError(
        'The token endpoint redirects elsewhere; the exchange has to happen at the endpoint discovery named.',
      );
    }
    if (!response.ok) {
      throw new BadRequestHttpError(`Token exchange failed with ${response.status}.`);
    }

    const body = await response.json() as { id_token?: string };
    if (!body.id_token) {
      throw new BadRequestHttpError('Token response carried no ID token.');
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
   * Reads the claim set out of a JWT without verifying its signature. Anything
   * that is not a JWT carrying a JSON object payload is a bad callback, not a
   * server fault, so it is refused the same way every other bad input is.
   */
  private decodeClaims(idToken: string): Record<string, unknown> {
    const parts = idToken.split('.');
    if (parts.length !== 3 || parts[1].length === 0) {
      throw new BadRequestHttpError('ID token is not a well-formed JWT.');
    }

    let payload: unknown;
    try {
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch {
      throw new BadRequestHttpError('ID token payload is not valid JSON.');
    }
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
      throw new BadRequestHttpError('ID token payload is not a JSON object.');
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
        signal: AbortSignal.timeout(PROFILE_TIMEOUT_MS),
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

  /**
   * Reads a body while counting bytes, so a response that never ends or that
   * lies about its length still costs a bounded amount of memory.
   */
  private async readCapped(webId: string, response: Response): Promise<string> {
    if (!response.body) {
      return '';
    }

    const decoder = new TextDecoder();
    let read = 0;
    let text = '';
    try {
      for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
        read += chunk.byteLength;
        if (read > PROFILE_MAX_BYTES) {
          throw new BadRequestHttpError(`The profile at ${webId} is larger than ${PROFILE_MAX_BYTES} bytes.`);
        }
        text += decoder.decode(chunk, { stream: true });
      }
    } catch (error) {
      if (BadRequestHttpError.isInstance(error)) {
        throw error;
      }
      throw new BadRequestHttpError(this.describeProfileFailure(webId, error));
    }
    return text + decoder.decode();
  }

  private describeProfileFailure(webId: string, error: unknown): string {
    const name = (error as { name?: string }).name;
    if (name === 'TimeoutError' || name === 'AbortError') {
      return `The profile at ${webId} did not answer within ${PROFILE_TIMEOUT_MS}ms.`;
    }
    return `Could not read the profile at ${webId}.`;
  }
}
