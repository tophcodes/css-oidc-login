export interface OidcEndpoints {
  authorization: string;
  token: string;
}

/** Issuer identifiers are compared without their trailing slashes. */
const withoutTrailingSlashes = (iri: string): string => iri.replace(/\/*$/u, '');

export class OidcDiscovery {
  private readonly issuer: string;
  private cached?: OidcEndpoints;

  public constructor(issuer: string) {
    this.issuer = issuer;
  }

  public async endpoints(): Promise<OidcEndpoints> {
    if (this.cached) {
      return this.cached;
    }

    const url = new URL('.well-known/openid-configuration', `${withoutTrailingSlashes(this.issuer)}/`);
    // A redirect here would move the search for the endpoints to a host that is
    // not the configured issuer, and every later check hangs off what this
    // document says. It is refused rather than followed.
    const response = await fetch(url, { redirect: 'manual' });
    if (response.status >= 300 && response.status < 400) {
      throw new Error(
        `Discovery for ${this.issuer} redirects elsewhere; the document has to be served from the issuer itself.`,
      );
    }
    if (!response.ok) {
      throw new Error(`Discovery for ${this.issuer} failed with ${response.status}.`);
    }

    const document = await response.json() as Record<string, unknown>;
    const issuer = document.issuer;
    const authorization = document.authorization_endpoint;
    const token = document.token_endpoint;
    // A document naming another issuer describes another provider, whatever URL
    // it was served from.
    if (typeof issuer !== 'string') {
      throw new Error(`Discovery for ${this.issuer} carried no issuer.`);
    }
    if (withoutTrailingSlashes(issuer) !== withoutTrailingSlashes(this.issuer)) {
      throw new Error(`Discovery for ${this.issuer} names ${issuer} as its issuer.`);
    }
    if (typeof authorization !== 'string') {
      throw new Error(`Discovery for ${this.issuer} carried no authorization_endpoint.`);
    }
    if (typeof token !== 'string') {
      throw new Error(`Discovery for ${this.issuer} carried no token_endpoint.`);
    }

    this.cached = { authorization, token };
    return this.cached;
  }
}
