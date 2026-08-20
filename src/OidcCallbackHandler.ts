import { Parser } from 'n3';
import { ResolveLoginHandler, BadRequestHttpError } from '@solid/community-server';
import type {
  AccountStore, CookieStore, JsonInteractionHandlerInput,
  JsonRepresentation, LoginOutputType,
} from '@solid/community-server';
import type { OidcDiscovery } from './OidcDiscovery';
import type { PendingLoginStore } from './PendingLoginStore';

/** Defined by the server's BaseWebIdStore, which also indexes `webId`. */
const WEBID_STORAGE_TYPE = 'webIdLink';

/** The only serialisation a profile is read as; anything else is refused. */
const PROFILE_MEDIA_TYPE = 'text/turtle';

/**
 * Predicate a profile uses to accept an external provider. Its own term
 * because no existing one carries this meaning — see `assertProfileTrustsIssuer`.
 */
export const DEFAULT_TRUST_PREDICATE = 'https://tophcodes.github.io/css-oidc-login/ns#loginIssuer';

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
   * Predicate a profile uses to accept this provider. Defaults to
   * {@link DEFAULT_TRUST_PREDICATE}. Never set this to `solid:oidcIssuer`.
   */
  trustPredicate?: string;
}

export class OidcCallbackHandler extends ResolveLoginHandler {
  private readonly args: OidcCallbackHandlerArgs;

  public constructor(args: OidcCallbackHandlerArgs) {
    super(args.accountStore, args.cookieStore);
    this.args = args;
  }

  public async login({ json }: JsonInteractionHandlerInput): Promise<JsonRepresentation<LoginOutputType>> {
    const { state, code } = json as { state?: string; code?: string };
    if (!state) {
      throw new BadRequestHttpError('Callback carried no state.');
    }
    if (!code) {
      throw new BadRequestHttpError('Callback carried no code.');
    }

    const pending = await this.args.store.consume(state);
    if (!pending) {
      throw new BadRequestHttpError('Unknown or expired state.');
    }

    const claims = await this.exchange(code, pending.codeVerifier);
    const claimName = this.args.webIdClaim ?? 'webid';
    const webId = claims[claimName];
    if (typeof webId !== 'string') {
      throw new BadRequestHttpError(`The provider returned no webid claim (${claimName}) for this user.`);
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

    await this.assertProfileTrustsIssuer(webId);

    this.logger.debug(`Logging in ${webId} through the external provider`);
    return { json: { accountId: links[0].accountId, remember: true }};
  }

  protected async exchange(code: string, codeVerifier: string): Promise<Record<string, unknown>> {
    const { token } = await this.args.discovery.endpoints();
    const response = await fetch(token, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.args.callbackUrl,
        client_id: this.args.clientId,
        client_secret: this.args.clientSecret,
        code_verifier: codeVerifier,
      }),
    });
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
   * A token naming several audiences additionally has to name this client as
   * its authorized party (OIDC Core 3.1.3.7): membership in `aud` alone would
   * let another client of the same provider mint a token for itself that also
   * lists this one.
   */
  private assertIssuedForUs(claims: Record<string, unknown>): void {
    const expectedIssuer = this.args.issuer.replace(/\/*$/u, '');
    if (typeof claims.iss !== 'string') {
      throw new BadRequestHttpError('ID token carried no issuer.');
    }
    const actualIssuer = claims.iss.replace(/\/*$/u, '');
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
    if (audience.length > 1 && claims.azp !== this.args.clientId) {
      throw new BadRequestHttpError(
        'ID token names several audiences without naming this client as the authorized party.',
      );
    }
  }

  /**
   * The per-account opt-in. A provider vouching for a WebID is not enough —
   * the profile that WebID resolves to must name that provider as one it
   * accepts authentication from. Without this, whoever runs the provider can
   * log in as anyone whose WebID they can name.
   *
   * The statement has to be one the profile's owner made: a named node in the
   * default graph of the document the WebID itself resolves to. A literal, a
   * statement parked in a named graph, or a document some redirect substituted
   * are all content that merely appears near the WebID, and none of them are
   * that assertion.
   *
   * Deliberately not `solid:oidcIssuer`: that predicate means "this issuer
   * mints my Solid-OIDC access tokens", and a Solid client reading it would
   * try to obtain DPoP-bound tokens from a provider that issues none.
   */
  private async assertProfileTrustsIssuer(webId: string): Promise<void> {
    const predicate = this.args.trustPredicate ?? DEFAULT_TRUST_PREDICATE;

    const response = await fetch(webId, {
      headers: { accept: PROFILE_MEDIA_TYPE },
      redirect: 'manual',
    });
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

    const body = await response.text();
    let quads;
    try {
      quads = new Parser({ baseIRI: webId }).parse(body);
    } catch {
      throw new BadRequestHttpError(`The profile at ${webId} could not be parsed as ${PROFILE_MEDIA_TYPE}.`);
    }

    const subject = webId;
    const expected = this.args.issuer.replace(/\/*$/u, '');

    const trusted = quads.some((quad): boolean =>
      quad.subject.value === subject &&
      quad.predicate.value === predicate &&
      quad.object.termType === 'NamedNode' &&
      quad.graph.termType === 'DefaultGraph' &&
      quad.object.value.replace(/\/*$/u, '') === expected);

    if (!trusted) {
      throw new BadRequestHttpError(
        `The profile at ${webId} does not accept authentication from ${expected}.`,
      );
    }
  }
}
