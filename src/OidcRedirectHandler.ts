import { randomBytes, createHash } from 'node:crypto';
import { JsonInteractionHandler } from '@solid/community-server';
import type { JsonRepresentation } from '@solid/community-server';
import type { OidcDiscovery } from './OidcDiscovery';
import type { PendingLoginStore } from './PendingLoginStore';

export interface OidcRedirectHandlerArgs {
  store: PendingLoginStore;
  discovery: OidcDiscovery;
  clientId: string;
  callbackUrl: string;
  /** Space-separated scopes. Providers that carry the WebID in a custom claim
   * usually need `profile` alongside `openid` for it to be emitted at all. */
  scopes?: string;
}

const base64url = (buf: Buffer): string => buf.toString('base64url');

export class OidcRedirectHandler extends JsonInteractionHandler {
  private readonly args: OidcRedirectHandlerArgs;

  public constructor(args: OidcRedirectHandlerArgs) {
    super();
    this.args = args;
  }

  public async handle(): Promise<JsonRepresentation> {
    const { authorization } = await this.args.discovery.endpoints();

    const state = base64url(randomBytes(32));
    const codeVerifier = base64url(randomBytes(32));
    const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());

    await this.args.store.create(state, { codeVerifier });

    const url = new URL(authorization);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.args.clientId);
    url.searchParams.set('redirect_uri', this.args.callbackUrl);
    url.searchParams.set('scope', this.args.scopes ?? 'openid profile');
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');

    return { json: { location: url.href }};
  }
}
