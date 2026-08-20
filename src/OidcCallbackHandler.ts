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
    // signature". The same section still requires iss and aud to be checked,
    // and those checks are not optional — see below.
    const payload = body.id_token.split('.')[1];
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;

    this.assertIssuedForUs(claims);
    return claims;
  }

  /**
   * Rejects a token that was not issued by the configured provider, or that
   * was issued to a different client of it. Without the audience check any
   * client registered at the same provider could mint a token this server
   * would accept.
   */
  private assertIssuedForUs(claims: Record<string, unknown>): void {
    const expectedIssuer = this.args.issuer.replace(/\/*$/u, '');
    const actualIssuer = typeof claims.iss === 'string' ? claims.iss.replace(/\/*$/u, '') : undefined;
    if (actualIssuer !== expectedIssuer) {
      throw new BadRequestHttpError(`ID token was issued by ${String(claims.iss)}, not by ${expectedIssuer}.`);
    }

    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audience.includes(this.args.clientId)) {
      throw new BadRequestHttpError('ID token was issued for a different client.');
    }
  }

  /**
   * The per-account opt-in. A provider vouching for a WebID is not enough —
   * the profile that WebID resolves to must name that provider as one it
   * accepts authentication from. Without this, whoever runs the provider can
   * log in as anyone whose WebID they can name.
   *
   * Deliberately not `solid:oidcIssuer`: that predicate means "this issuer
   * mints my Solid-OIDC access tokens", and a Solid client reading it would
   * try to obtain DPoP-bound tokens from a provider that issues none.
   */
  private async assertProfileTrustsIssuer(webId: string): Promise<void> {
    const predicate = this.args.trustPredicate ?? DEFAULT_TRUST_PREDICATE;

    const response = await fetch(webId, { headers: { accept: 'text/turtle' }});
    if (!response.ok) {
      throw new BadRequestHttpError(`Could not read the profile at ${webId} (${response.status}).`);
    }

    const quads = new Parser({ baseIRI: webId }).parse(await response.text());
    const subject = webId;
    const expected = this.args.issuer.replace(/\/*$/u, '');

    const trusted = quads.some((quad): boolean =>
      quad.subject.value === subject &&
      quad.predicate.value === predicate &&
      quad.object.value.replace(/\/*$/u, '') === expected);

    if (!trusted) {
      throw new BadRequestHttpError(
        `The profile at ${webId} does not accept authentication from ${expected}.`,
      );
    }
  }
}
