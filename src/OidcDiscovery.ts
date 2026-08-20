import { HttpError, InternalServerError } from '@solid/community-server';
import { readCapped, RESPONSE_MAX_BYTES, RESPONSE_TIMEOUT_MS } from './limits.ts';

export interface OidcEndpoints {
  authorization: string;
  token: string;
}

/**
 * Nothing that goes wrong here is anything a caller sent: the issuer is
 * configured, the document is the provider's, and a login only ever arrives
 * after it. So a failure is reported as one of the provider's rather than as a
 * bad request — 502 for a provider that answered badly, and 504 for one that
 * did not answer within the deadline, which is a wait rather than an answer
 * and the one case an operator can tell apart at a glance.
 */
const providerFailed = (message: string): HttpError => new HttpError(502, 'BadGatewayHttpError', message);
const providerTimedOut = (message: string): HttpError => new HttpError(504, 'GatewayTimeoutHttpError', message);

/** Issuer identifiers are compared without their trailing slashes. */
const withoutTrailingSlashes = (iri: string): string => iri.replace(/\/*$/u, '');

/**
 * Whether a value can be used as a URL at all. Both endpoints the document
 * names end up in a `fetch` and one of them in a `new URL`, and a string that
 * is neither is a document this server cannot act on however well-formed the
 * JSON around it was.
 */
const isAbsoluteUrl = (value: string): boolean => {
  try {
    void new URL(value);
    return true;
  } catch {
    return false;
  }
};

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

    // The issuer is configuration, so an issuer that is no URL is this
    // deployment's own failure and nobody else's — said so here rather than
    // left to surface as whatever `new URL` raises, which is an unclassified
    // fault of this server that names neither the setting nor its value.
    if (!isAbsoluteUrl(`${withoutTrailingSlashes(this.issuer)}/`)) {
      throw new InternalServerError(
        `The configured issuer ${this.issuer} is not an absolute URL, so this server cannot look up ` +
        'the discovery document that every later check hangs off.',
      );
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
        throw providerTimedOut(`Discovery for ${this.issuer} did not answer within ${RESPONSE_TIMEOUT_MS}ms.`);
      }
      throw providerFailed(`Discovery for ${this.issuer} could not be read.`);
    }
    if (response.status >= 300 && response.status < 400) {
      throw providerFailed(
        `Discovery for ${this.issuer} redirects elsewhere; the document has to be served from the issuer itself.`,
      );
    }
    if (!response.ok) {
      throw providerFailed(`Discovery for ${this.issuer} failed with ${response.status}.`);
    }

    const document = this.parse(await this.read(response));
    const issuer = document.issuer;
    const authorization = document.authorization_endpoint;
    const token = document.token_endpoint;
    // A document naming another issuer describes another provider, whatever URL
    // it was served from.
    if (typeof issuer !== 'string') {
      throw providerFailed(`Discovery for ${this.issuer} carried no issuer.`);
    }
    if (withoutTrailingSlashes(issuer) !== withoutTrailingSlashes(this.issuer)) {
      throw providerFailed(`Discovery for ${this.issuer} names ${issuer} as its issuer.`);
    }
    if (typeof authorization !== 'string') {
      throw providerFailed(`Discovery for ${this.issuer} carried no authorization_endpoint.`);
    }
    if (typeof token !== 'string') {
      throw providerFailed(`Discovery for ${this.issuer} carried no token_endpoint.`);
    }
    // An endpoint that is a string but no URL is a document that cannot be
    // acted on. Left to the caller, the authorization one surfaces as whatever
    // `new URL` raises where the login is built — an unclassified fault of
    // this server for a document the provider wrote.
    if (!isAbsoluteUrl(authorization)) {
      throw providerFailed(
        `Discovery for ${this.issuer} names an authorization_endpoint that is not an absolute URL.`,
      );
    }
    if (!isAbsoluteUrl(token)) {
      throw providerFailed(
        `Discovery for ${this.issuer} names a token_endpoint that is not an absolute URL.`,
      );
    }

    this.cached = { authorization, token };
    return this.cached;
  }

  /**
   * Reads the document, mapping a read that gives up part-way. The deadline
   * covers the body as well as the headers, so an issuer that answers and then
   * trickles trips it here rather than at the fetch, and what ends such a read
   * is not an `HttpError` — left unmapped it would be reported as an internal
   * fault of this server for a wait on somebody else's host.
   */
  private async read(response: Response): Promise<string> {
    try {
      return await readCapped(
        response,
        (): Error => providerFailed(`Discovery for ${this.issuer} is larger than ${RESPONSE_MAX_BYTES} bytes.`),
      );
    } catch (error) {
      if (HttpError.isInstance(error)) {
        throw error;
      }
      const name = (error as { name?: string }).name;
      if (name === 'TimeoutError' || name === 'AbortError') {
        throw providerTimedOut(`Discovery for ${this.issuer} did not answer within ${RESPONSE_TIMEOUT_MS}ms.`);
      }
      throw providerFailed(`Discovery for ${this.issuer} could not be read.`);
    }
  }

  private parse(body: string): Record<string, unknown> {
    let document: unknown;
    try {
      document = JSON.parse(body);
    } catch {
      throw providerFailed(`Discovery for ${this.issuer} is not valid JSON.`);
    }
    if (typeof document !== 'object' || document === null || Array.isArray(document)) {
      throw providerFailed(`Discovery for ${this.issuer} is not a JSON object.`);
    }
    return document as Record<string, unknown>;
  }
}
