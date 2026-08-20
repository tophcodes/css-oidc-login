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
 * Whether a value is a URL this server may act on: an absolute `https:` one.
 *
 * `new URL` merely parsing is not enough on either side of this.
 *
 * It is too permissive for what the values are used for. `javascript:`,
 * `data:` and `file:` all parse, and the authorization endpoint is handed to a
 * browser as the address to navigate to — a document naming
 * `javascript:...` would run as script on this server's own origin, granted by
 * the one party this package's grant model exists to distrust.
 *
 * It is also too weak for what the issuer is put through: for an opaque-path
 * scheme such as `urn:` or `mailto:` the value parses but resolving a relative
 * path against it does not, so a check that only parses passes a value the
 * next line throws on.
 *
 * Plain `http:` is refused with the rest. The pending-login cookie already
 * requires this server to be served over HTTPS, and a token exchange over
 * `http:` would put the client secret on the wire in clear — a provider
 * reachable only over plain HTTP cannot be used safely from here, so it is
 * named rather than quietly accepted.
 */
const isHttpsUrl = (value: string): boolean => {
  try {
    return new URL(value).protocol === 'https:';
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

    // The issuer is configuration, so an issuer this server cannot use is this
    // deployment's own failure and nobody else's — said so here rather than
    // left to surface as whatever `new URL` raises, which is an unclassified
    // fault of this server that names neither the setting nor its value. The
    // check is on the same base string the next line resolves against, so it
    // tests exactly what that resolution needs.
    if (!isHttpsUrl(`${withoutTrailingSlashes(this.issuer)}/`)) {
      throw new InternalServerError(
        `The configured issuer ${this.issuer} is not an absolute HTTPS URL, so this server cannot look up ` +
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
    // An endpoint outside this is a document that cannot be acted on, and the
    // authorization one is not merely unusable but dangerous: it leaves here as
    // the address a browser is told to go to, so a scheme other than `https:`
    // is refused before it can become one.
    if (!isHttpsUrl(authorization)) {
      throw providerFailed(
        `Discovery for ${this.issuer} names an authorization_endpoint that is not an absolute HTTPS URL.`,
      );
    }
    if (!isHttpsUrl(token)) {
      throw providerFailed(
        `Discovery for ${this.issuer} names a token_endpoint that is not an absolute HTTPS URL.`,
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
