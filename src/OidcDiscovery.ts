import { readCapped, RESPONSE_MAX_BYTES, RESPONSE_TIMEOUT_MS } from './limits.ts';

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
    let response: Response;
    try {
      response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(RESPONSE_TIMEOUT_MS) });
    } catch (error) {
      const name = (error as { name?: string }).name;
      if (name === 'TimeoutError' || name === 'AbortError') {
        throw new Error(`Discovery for ${this.issuer} did not answer within ${RESPONSE_TIMEOUT_MS}ms.`);
      }
      throw new Error(`Discovery for ${this.issuer} could not be read.`);
    }
    if (response.status >= 300 && response.status < 400) {
      throw new Error(
        `Discovery for ${this.issuer} redirects elsewhere; the document has to be served from the issuer itself.`,
      );
    }
    if (!response.ok) {
      throw new Error(`Discovery for ${this.issuer} failed with ${response.status}.`);
    }

    const document = this.parse(await readCapped(
      response,
      (): Error => new Error(`Discovery for ${this.issuer} is larger than ${RESPONSE_MAX_BYTES} bytes.`),
    ));
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

  private parse(body: string): Record<string, unknown> {
    let document: unknown;
    try {
      document = JSON.parse(body);
    } catch {
      throw new Error(`Discovery for ${this.issuer} is not valid JSON.`);
    }
    if (typeof document !== 'object' || document === null || Array.isArray(document)) {
      throw new Error(`Discovery for ${this.issuer} is not a JSON object.`);
    }
    return document as Record<string, unknown>;
  }
}
