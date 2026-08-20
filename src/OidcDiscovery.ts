export interface OidcEndpoints {
  authorization: string;
  token: string;
}

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

    const url = new URL('.well-known/openid-configuration', `${this.issuer.replace(/\/*$/u, '')}/`);
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Discovery for ${this.issuer} failed with ${response.status}.`);
    }

    const document = await response.json() as Record<string, unknown>;
    const authorization = document.authorization_endpoint;
    const token = document.token_endpoint;
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
