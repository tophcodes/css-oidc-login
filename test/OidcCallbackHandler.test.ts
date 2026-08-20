import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DataFactory } from 'n3';
import { RepresentationMetadata } from '@solid/community-server';
import {
  OidcCallbackHandler, GRANT_ISSUER_PREDICATE, GRANT_SUBJECT_PREDICATE,
} from '../src/OidcCallbackHandler.ts';
import { PendingLoginStore } from '../src/PendingLoginStore.ts';
import {
  BEYOND_PATIENCE_MS, DEADLINE_BOUND_MS, endlessBody, neverAnswers, stallsMidBody,
} from './bounds.ts';

/** Predicates are read off a store instance, the way the handlers read them. */
const { cookiePredicate, setCookiePredicate } = new PendingLoginStore();

const { namedNode } = DataFactory;

const WEBID = 'https://pod.example/alice/profile/card#me';
const TRUST_PREDICATE = 'https://tophcodes.github.io/css-oidc-login/ns#externalLogin';
const TARGET = { path: 'https://pod.example/cb' };
/** The subject the provider assigns to the person whose WebID this is. */
const SUBJECT = 'subject-alice';
/** The handle the browser that started a login holds in its cookie. */
const HANDLE = 'handle-of-the-browser-that-started-the-login';

const makeHandler = (
  claims: Record<string, unknown>,
  links: unknown[],
  webIdClaim?: string,
  trustPredicate?: string,
) => {
  const store = new PendingLoginStore();
  const calls: unknown[][] = [];
  const settings: unknown[][] = [];
  const handler = new OidcCallbackHandler({
    accountStore: {
      updateSetting: async (...args: unknown[]) => {
        settings.push(args);
      },
      getSetting: async () => undefined,
    } as never,
    cookieStore: { generate: async () => 'account-cookie', delete: async () => undefined } as never,
    store,
    storage: {
      find: async (type: string, query: unknown) => {
        calls.push([type, query]);
        return links;
      },
    } as never,
    discovery: { endpoints: async () => ({ authorization: 'a', token: 'https://idp.example/token' }) } as never,
    issuer: 'https://idp.example',
    clientId: 'pod-client',
    clientSecret: 'shh',
    callbackUrl: 'https://pod.example/cb',
    webIdClaim,
    trustPredicate,
  });
  // Neither the provider nor the profile fetch is under test in these cases;
  // each has its own tests below.
  (handler as unknown as { exchange: unknown }).exchange = async () => claims;
  (handler as unknown as { assertProfileGrantsLogin: unknown }).assertProfileGrantsLogin = async () => undefined;
  return { handler, store, calls, settings };
};

/** Drops the stubs so a test runs the real token exchange and profile check. */
const unstub = (handler: OidcCallbackHandler, ...names: string[]): void => {
  for (const name of names) {
    delete (handler as unknown as Record<string, unknown>)[name];
  }
};

/** Registers a login in progress, as the redirect handler would have done. */
const start = async (store: PendingLoginStore, state: string, handle = HANDLE): Promise<void> =>
  store.create(state, { codeVerifier: 'v', handle });

/**
 * The request the callback route receives. `handle` is what the browser's
 * cookie jar contributes: `null` stands for a browser that holds no such
 * cookie, which is every browser except the one that started the login.
 */
const callback = (json: unknown, handle: string | null = HANDLE): never => {
  const metadata = new RepresentationMetadata(TARGET);
  if (handle !== null) {
    metadata.add(namedNode(cookiePredicate), handle);
  }
  return { method: 'POST', target: TARGET, json, metadata } as never;
};

const isBadRequest = (error: unknown): boolean =>
  (error as { statusCode?: number }).statusCode === 400;

const statusOf = (error: unknown): number | undefined => (error as { statusCode?: number }).statusCode;

/**
 * What an error says and whose failure it is reported as, in one predicate.
 * The status is asserted rather than returned as a boolean so that a test
 * which fails says which party the failure was handed to, instead of only
 * that some error did not match.
 */
const isFailure = (status: number, message: RegExp) => (error: unknown): boolean => {
  assert.equal(
    statusOf(error),
    status,
    `expected a ${status}, got ${statusOf(error)} — the message was: ${String(error)}`,
  );
  assert.match(String(error), message);
  return true;
};

const profileGranting = (
  issuer: string,
  subject: string = SUBJECT,
  predicate = TRUST_PREDICATE,
): string => `
  <${WEBID}> <${predicate}> [
    <${GRANT_ISSUER_PREDICATE}> <${issuer}> ;
    <${GRANT_SUBJECT_PREDICATE}> "${subject}"
  ] .
`;

test('logs in the account linked to the WebID in the claim', async () => {
  const { handler, store, calls } = makeHandler(
    { webid: WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
  );
  await start(store, 's1');

  const { json } = await handler.login(callback({ state: 's1', code: 'c' }));

  assert.equal(json.accountId, 'acc-1');
  assert.deepEqual(calls, [['webIdLink', { webId: WEBID }]]);
});

test('honours a custom claim name', async () => {
  const { handler, store } = makeHandler(
    { 'http://example.org/webid': WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-2' }],
    'http://example.org/webid',
  );
  await start(store, 's2');

  const { json } = await handler.login(callback({ state: 's2', code: 'c' }));
  assert.equal(json.accountId, 'acc-2');
});

// The documentation names the missing `profile` scope as what this looks
// like, which makes it an operator who configured the scopes or the claim
// mapping — never the person at the browser, who cannot act on it at all.
test('reports a token without the claim as the provider\'s failure', async () => {
  const { handler, store } = makeHandler({ sub: SUBJECT }, []);
  await start(store, 's3');

  await assert.rejects(
    handler.login(callback({ state: 's3', code: 'c' })),
    isFailure(502, /no webid claim/u),
  );
});

// A claim that is a string but names nothing this server can fetch is the same
// failure: what came back was not a WebID, and the caller did not choose it.
test('reports a claim that is no http URL as the provider\'s failure', async () => {
  for (const [ index, claim ] of [ 'not a url', 'urn:uuid:1', 'https://pod.example/#me\nWARN', 5 ].entries()) {
    const { handler, store } = makeHandler({ webid: claim, sub: SUBJECT }, []);
    await start(store, `s3-claim-${index}`);

    await assert.rejects(
      handler.login(callback({ state: `s3-claim-${index}`, code: 'c' })),
      isFailure(502, /webid claim/u),
    );
  }
});

// `sub` is REQUIRED of every ID token, so a token without one is a token the
// provider was never allowed to compose.
test('reports a token without a subject as the provider\'s failure', async () => {
  const { handler, store } = makeHandler({ webid: WEBID }, [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }]);
  await start(store, 's3-sub');

  await assert.rejects(
    handler.login(callback({ state: 's3-sub', code: 'c' })),
    isFailure(502, /no subject/u),
  );
});

// Nothing in the request is wrong and no host failed: the identity is
// established and this server will not log it in, which is what a 403 says.
test('refuses a WebID no account is linked to', async () => {
  const { handler, store } = makeHandler({ webid: 'https://elsewhere.example/#me', sub: SUBJECT }, []);
  await start(store, 's4');

  await assert.rejects(handler.login(callback({ state: 's4', code: 'c' })), isFailure(403, /not linked/u));
});

// Which of several linked accounts was meant is not knowable from the token,
// and the storage does not promise an order, so there is nothing to pick from.
test('rejects a WebID that is linked to more than one account', async () => {
  const { handler, store } = makeHandler({ webid: WEBID, sub: SUBJECT }, [
    { id: 'l1', webId: WEBID, accountId: 'acc-1' },
    { id: 'l2', webId: WEBID, accountId: 'acc-2' },
  ]);
  await start(store, 's-multi');

  // The conflict is in this server's own account data, not in the request and
  // not at either host, so it is answered as the conflict it is.
  await assert.rejects(
    handler.login(callback({ state: 's-multi', code: 'c' })),
    isFailure(409, /linked to 2 accounts/u),
  );
});

test('rejects an unknown state', async () => {
  const { handler } = makeHandler({ webid: WEBID, sub: SUBJECT }, []);
  await assert.rejects(handler.login(callback({ state: 'never-issued', code: 'c' })), /state/u);
});

test('rejects a state that was already used', async () => {
  const { handler, store } = makeHandler(
    { webid: WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
  );
  await start(store, 's-replay');

  const { json } = await handler.login(callback({ state: 's-replay', code: 'c' }));
  assert.equal(json.accountId, 'acc-1');

  await assert.rejects(
    handler.login(callback({ state: 's-replay', code: 'c' })),
    /Unknown or expired state/u,
  );
});

test('rejects a callback with no code', async () => {
  const { handler, store } = makeHandler({ webid: WEBID, sub: SUBJECT }, []);
  await start(store, 's5');

  await assert.rejects(handler.login(callback({ state: 's5' })), /code/u);
});

// Binding the login to a browser. Everything below is written as the attack it
// refuses: the state and the code are exactly what an attacker has, and the
// cookie is exactly what they do not.

test('refuses a stolen code and state replayed by someone who did not start the login', async () => {
  const { handler, store } = makeHandler(
    { webid: WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
  );
  // The victim starts a login; the attacker reads code and state off the wire,
  // out of a proxy log, or out of a Referer header, and posts them first.
  await start(store, 'stolen-state');

  await assert.rejects(
    handler.login(callback({ state: 'stolen-state', code: 'stolen-code' }, null)),
    (error: unknown): boolean => isBadRequest(error) && /cookie/u.test(String(error)),
  );
});

test('does not spend the pending login for a caller that cannot show the cookie', async () => {
  const { handler, store } = makeHandler(
    { webid: WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
  );
  await start(store, 'victim-state');

  await assert.rejects(handler.login(callback({ state: 'victim-state', code: 'c' }, null)));

  // The victim's own browser can still finish the login it started.
  const { json } = await handler.login(callback({ state: 'victim-state', code: 'c' }));
  assert.equal(json.accountId, 'acc-1');
});

test('refuses a callback answered by a browser holding a different login\'s cookie', async () => {
  const { handler, store } = makeHandler(
    { webid: WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
  );
  await start(store, 'victim-state', 'victim-handle');
  await start(store, 'attacker-state', 'attacker-handle');

  // The attacker holds a valid cookie — their own — and tries it against the
  // login somebody else started.
  await assert.rejects(
    handler.login(callback({ state: 'victim-state', code: 'c' }, 'attacker-handle')),
    (error: unknown): boolean => isBadRequest(error) && /does not belong to this login/u.test(String(error)),
  );
});

// Spending the login before the handle is checked would protect only the
// browser that holds no cookie at all. Anyone with a leaked state and a cookie
// of their own could still destroy a login in progress, and two logins started
// in one browser would take each other down.
test('does not spend the pending login for a caller holding another login\'s cookie', async () => {
  const { handler, store } = makeHandler(
    { webid: WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
  );
  await start(store, 'victim-state', 'victim-handle');

  await assert.rejects(
    handler.login(callback({ state: 'victim-state', code: 'c' }, 'attacker-handle')),
    (error: unknown): boolean => isBadRequest(error) && /does not belong to this login/u.test(String(error)),
  );

  // The victim's own browser can still finish the login it started.
  const { json } = await handler.login(callback({ state: 'victim-state', code: 'c' }, 'victim-handle'));
  assert.equal(json.accountId, 'acc-1');
});

// Login CSRF: the attacker completes a login at the provider themselves, then
// makes the victim's browser post their code and state cross-site. The cookie
// is SameSite=Strict, so the victim's browser sends none, and the callback is
// looking at a request that carries a perfectly valid state.
test('refuses a cross-site form submission that would log the victim in as the attacker', async () => {
  const { handler, store } = makeHandler(
    { webid: 'https://pod.example/mallory/profile/card#me', sub: 'subject-mallory' },
    [{ id: 'l9', webId: 'https://pod.example/mallory/profile/card#me', accountId: 'attacker-account' }],
  );
  await start(store, 'attacker-state', 'attacker-handle');

  await assert.rejects(
    handler.login(callback({ state: 'attacker-state', code: 'attacker-code' }, null)),
    (error: unknown): boolean => isBadRequest(error) && /cookie/u.test(String(error)),
  );
});

// The next block exercises the real exchange path, because the checks it covers
// live there. OIDC Core 3.1.3.7 requires them even when the signature is not
// re-verified.

const idToken = (claims: Record<string, unknown>): string =>
  `header.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`;

/** Replaces fetch with one that answers the token endpoint with `body`. */
const withTokenBody = async (body: unknown, fn: () => Promise<void>): Promise<void> => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify(body), { status: 200 })
  ) as unknown as typeof fetch;
  try {
    await fn();
  } finally {
    globalThis.fetch = original;
  }
};

const withTokenResponse = async (claims: Record<string, unknown>, fn: () => Promise<void>): Promise<void> =>
  withTokenBody({ id_token: idToken(claims) }, fn);

/** A handler whose exchange runs for real; the profile check stays stubbed. */
const exchangingHandler = async (state: string) => {
  const { handler, store } = makeHandler({}, [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }]);
  unstub(handler, 'exchange');
  await start(store, state);
  return handler;
};

test('rejects a token issued by a different provider', async () => {
  const handler = await exchangingHandler('s6');

  await withTokenResponse(
    { iss: 'https://evil.example', aud: 'pod-client', sub: SUBJECT, webid: WEBID },
    async () => {
      await assert.rejects(
        handler.login(callback({ state: 's6', code: 'c' })),
        isFailure(502, /other than the configured https:\/\/idp\.example/u),
      );
    },
  );
});

test('rejects a token issued for a different client of the same provider', async () => {
  const handler = await exchangingHandler('s7');

  await withTokenResponse(
    { iss: 'https://idp.example', aud: 'some-other-client', sub: SUBJECT, webid: WEBID },
    async () => {
      await assert.rejects(
        handler.login(callback({ state: 's7', code: 'c' })),
        isFailure(502, /different client/u),
      );
    },
  );
});

test('rejects a token that carries no issuer', async () => {
  const handler = await exchangingHandler('s-no-iss');

  await withTokenResponse({ aud: 'pod-client', sub: SUBJECT, webid: WEBID }, async () => {
    await assert.rejects(
      handler.login(callback({ state: 's-no-iss', code: 'c' })),
      isFailure(502, /no issuer/u),
    );
  });
});

test('rejects a token that carries no audience', async () => {
  const handler = await exchangingHandler('s-no-aud');

  await withTokenResponse({ iss: 'https://idp.example', sub: SUBJECT, webid: WEBID }, async () => {
    await assert.rejects(
      handler.login(callback({ state: 's-no-aud', code: 'c' })),
      isFailure(502, /no audience/u),
    );
  });
});

test('rejects a token whose aud array does not contain our client', async () => {
  const handler = await exchangingHandler('s-foreign-aud');

  await withTokenResponse(
    { iss: 'https://idp.example', aud: ['other', 'yet-another'], azp: 'other', sub: SUBJECT, webid: WEBID },
    async () => {
      await assert.rejects(
        handler.login(callback({ state: 's-foreign-aud', code: 'c' })),
        isFailure(502, /different client/u),
      );
    },
  );
});

test('accepts a token whose aud is an array containing our client and whose azp names us', async () => {
  const handler = await exchangingHandler('s8');

  await withTokenResponse(
    { iss: 'https://idp.example/', aud: ['pod-client', 'other'], azp: 'pod-client', sub: SUBJECT, webid: WEBID },
    async () => {
      const { json } = await handler.login(callback({ state: 's8', code: 'c' }));
      assert.equal(json.accountId, 'acc-1');
    },
  );
});

// A second client of the same provider can list this one among the audiences
// of a token it minted for itself. OIDC Core 3.1.3.7 makes azp the deciding
// claim in that case: without it naming this client, the token is not ours.
test('rejects a multi-audience token that does not name us as the authorized party', async () => {
  const handler = await exchangingHandler('s-azp-missing');

  await withTokenResponse(
    { iss: 'https://idp.example', aud: ['rogue-client', 'pod-client'], sub: SUBJECT, webid: WEBID },
    async () => {
      await assert.rejects(
        handler.login(callback({ state: 's-azp-missing', code: 'c' })),
        isFailure(502, /authorized party/u),
      );
    },
  );
});

test('rejects a multi-audience token whose azp names another client', async () => {
  const handler = await exchangingHandler('s-azp-wrong');

  await withTokenResponse(
    {
      iss: 'https://idp.example',
      aud: [ 'rogue-client', 'pod-client' ],
      azp: 'rogue-client',
      sub: SUBJECT,
      webid: WEBID,
    },
    async () => {
      await assert.rejects(
        handler.login(callback({ state: 's-azp-wrong', code: 'c' })),
        isFailure(502, /authorized party/u),
      );
    },
  );
});

// A single audience does not make azp advisory: a provider mints a token whose
// aud names this client and whose azp names the requesting one whenever a
// second client asks it for a token addressed here. That token is not ours.
test('rejects a single-audience token whose azp names another client', async () => {
  const handler = await exchangingHandler('s-azp-single-foreign');

  await withTokenResponse(
    { iss: 'https://idp.example', aud: 'pod-client', azp: 'rogue-client', sub: SUBJECT, webid: WEBID },
    async () => {
      await assert.rejects(
        handler.login(callback({ state: 's-azp-single-foreign', code: 'c' })),
        isFailure(502, /authorized party/u),
      );
    },
  );
});

test('accepts a single-audience token whose azp names us', async () => {
  const handler = await exchangingHandler('s-azp-single-ok');

  await withTokenResponse(
    { iss: 'https://idp.example', aud: 'pod-client', azp: 'pod-client', sub: SUBJECT, webid: WEBID },
    async () => {
      const { json } = await handler.login(callback({ state: 's-azp-single-ok', code: 'c' }));
      assert.equal(json.accountId, 'acc-1');
    },
  );
});

// The claim is a string in the spec; anything else has to be refused rather
// than compared after a coercion that could make it match.
test('rejects a token whose azp is not a string', async () => {
  const handler = await exchangingHandler('s-azp-not-string');

  await withTokenResponse(
    { iss: 'https://idp.example', aud: 'pod-client', azp: [ 'pod-client' ], sub: SUBJECT, webid: WEBID },
    async () => {
      await assert.rejects(
        handler.login(callback({ state: 's-azp-not-string', code: 'c' })),
        isFailure(502, /authorized party/u),
      );
    },
  );
});

/** A JWT carrying `payload` verbatim, however little of a claim set it is. */
const jwtCarrying = (payload: string): string =>
  `header.${Buffer.from(payload).toString('base64url')}.signature`;

/** Runs one exchange against a token endpoint that answers `body` with a 200. */
const answeredExchange = async (state: string, body: string): Promise<{ status?: number; message: string }> => {
  const handler = await exchangingHandler(state);

  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response(body, { status: 200 })) as unknown as typeof fetch;
  try {
    await handler.login(callback({ state, code: 'c' }));
    throw new Error(`the answer was taken for a token: ${body}`);
  } catch (error) {
    return { status: statusOf(error), message: String(error) };
  } finally {
    globalThis.fetch = original;
  }
};

/**
 * The measured mapping, one row per answer a token endpoint can say the
 * exchange succeeded with. A 200 is the provider saying it did, so everything
 * in what follows is the provider's own composition: the caller brought a
 * code, and what was minted for it was not theirs to write. An answer this
 * server cannot make sense of is that provider answering in a way that is no
 * answer at all — the same thing a body that never arrives is, and the same
 * thing an unreadable refusal is, so it is reported as the same failure.
 *
 * Reported as the caller's instead, an operator who configures scopes without
 * `openid`, or registers a client the provider issues no ID token for, sees
 * every login die as somebody's bad request, among all the callbacks that
 * genuinely are one — which is the one failure they could have acted on.
 */
const UNREADABLE_TOKEN_ANSWERS: { body: string; says: RegExp; why: string }[] = [
  { body: '<html>oops</html>', says: /not valid JSON/u, why: 'an answer that is not JSON' },
  { body: '[]', says: /not a JSON object/u, why: 'an answer that is not an object' },
  { body: '{"access_token":"a"}', says: /carried no ID token/u, why: 'an answer with no ID token in it' },
  { body: '{"id_token":""}', says: /carried no ID token/u, why: 'an empty ID token' },
  { body: '{"id_token":5}', says: /carried no ID token/u, why: 'an ID token that is not a string' },
  { body: '{"id_token":{}}', says: /carried no ID token/u, why: 'an ID token that is not a string' },
  { body: '{"id_token":"garbage"}', says: /not a well-formed JWT/u, why: 'an ID token that is not a JWT' },
  { body: '{"id_token":"header..signature"}', says: /not a well-formed JWT/u, why: 'a JWT with no payload' },
  {
    body: JSON.stringify({ id_token: jwtCarrying('not json') }),
    says: /payload is not valid JSON/u,
    why: 'a payload that is not JSON',
  },
  {
    body: JSON.stringify({ id_token: jwtCarrying('[]') }),
    says: /payload is not a JSON object/u,
    why: 'a payload that is not an object',
  },
];

test('reports an answer it cannot make sense of as the provider\'s failure', async () => {
  for (const [ index, row ] of UNREADABLE_TOKEN_ANSWERS.entries()) {
    const { status, message } = await answeredExchange(`s-unreadable-${index}`, row.body);
    assert.equal(
      status,
      502,
      `${row.why} was reported as ${status}, not as 502 — the message was: ${message}`,
    );
    assert.match(message, row.says);
  }
});

// A 307 or 308 replays the POST body at the redirect target, handing the client
// secret and the authorization code to whoever the response names. The stub
// follows redirects unless asked not to, so an implementation that leaves the
// default in place completes the login against the other host.
test('refuses to follow a redirect away from the token endpoint', async () => {
  const handler = await exchangingHandler('s-token-redirect');

  const original = globalThis.fetch;
  const leaked: unknown[] = [];
  globalThis.fetch = (async (input: unknown, init?: { redirect?: string; body?: unknown }) => {
    if (String(input).includes('elsewhere.example')) {
      leaked.push(String(init?.body));
      return new Response(JSON.stringify({
        id_token: idToken({ iss: 'https://idp.example', aud: 'pod-client', sub: SUBJECT, webid: WEBID }),
      }), { status: 200 });
    }
    if (init?.redirect === 'manual') {
      return new Response(null, { status: 307, headers: { location: 'https://elsewhere.example/token' }});
    }
    return globalThis.fetch('https://elsewhere.example/token', init as never);
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-token-redirect', code: 'c' })),
      (error: unknown): boolean => statusOf(error) === 502 && /redirects elsewhere/u.test(String(error)),
    );
    assert.deepEqual(leaked, [], 'the request body reached the redirect target');
  } finally {
    globalThis.fetch = original;
  }
});

// The per-person opt-in. These run the real profile check.

interface ProfileResponse {
  body?: string | null;
  status?: number;
  contentType?: string | null;
  location?: string;
}

const withProfile = async (
  profile: string | ProfileResponse,
  fn: () => Promise<void>,
): Promise<void> => {
  const { body = '', status = 200, contentType = 'text/turtle', location } =
    typeof profile === 'string' ? { body: profile } as ProfileResponse : profile;
  const headers: Record<string, string> = {};
  if (contentType !== null) {
    headers['content-type'] = contentType;
  }
  if (location) {
    headers.location = location;
  }
  // A body given to Response gets text/plain by default, so a profile served
  // without any media type has to have the header taken off again.
  const profileResponse = (): Response => {
    const response = new Response(status === 204 || status >= 300 ? null : body, { status, headers });
    if (contentType === null) {
      response.headers.delete('content-type');
    }
    return response;
  };

  // Answering unconditionally would leave the redirect guard untested: a stub
  // that hands back the 3xx no matter what is asked for cannot tell an
  // implementation that refuses to follow redirects from one that follows them
  // silently. So the stub follows, the way a real fetch would, and serves the
  // document at the other end.
  const followed = (): Response => new Response(profileGranting('https://idp.example'), {
    status: 200,
    headers: { 'content-type': 'text/turtle' },
  });

  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown, init?: { redirect?: string }) => {
    if (String(input).includes('/token')) {
      return new Response(JSON.stringify({
        id_token: idToken({ iss: 'https://idp.example', aud: 'pod-client', sub: SUBJECT, webid: WEBID }),
      }), { status: 200 });
    }
    if (status >= 300 && status < 400 && init?.redirect !== 'manual') {
      return followed();
    }
    return profileResponse();
  }) as unknown as typeof fetch;
  try {
    await fn();
  } finally {
    globalThis.fetch = original;
  }
};

/** A handler that runs both the real exchange and the real profile check. */
const profileCheckingHandler = async (state: string, trustPredicate?: string) => {
  const { handler, store } = makeHandler(
    {},
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
    undefined,
    trustPredicate,
  );
  unstub(handler, 'exchange', 'assertProfileGrantsLogin');
  await start(store, state);
  return handler;
};

/**
 * A profile the check will not use, and whose failure it is reported as. The
 * two are not the same party: a host that will not serve the document is an
 * upstream this server waits on, exactly as the token endpoint is, while a
 * document that arrives and grants nothing is a permission that was never
 * given. Neither is the browser that brought a state and a code.
 */
const assertProfileRejected = async (
  state: string,
  profile: string | ProfileResponse,
  status: number,
  message: RegExp,
  trustPredicate?: string,
): Promise<void> => {
  const handler = await profileCheckingHandler(state, trustPredicate);
  await withProfile(profile, async () => {
    await assert.rejects(handler.login(callback({ state, code: 'c' })), isFailure(status, message));
  });
};

test('refuses a valid token when the profile does not name the provider', async () => {
  await assertProfileRejected(
    's9',
    profileGranting('https://other-idp.example'),
    403,
    /does not accept authentication/u,
  );
});

test('accepts when the profile grants this subject at the provider', async () => {
  const handler = await profileCheckingHandler('s10');

  await withProfile(profileGranting('https://idp.example'), async () => {
    const { json } = await handler.login(callback({ state: 's10', code: 'c' }));
    assert.equal(json.accountId, 'acc-1');
  });
});

// The grant names a person, not a provider. Everyone else at the same provider
// is a stranger, including the one who arranged for the victim's WebID to be
// in their own token — which is the whole reason the subject is bound.
test('refuses a token for a different subject at the provider the profile does name', async () => {
  const handler = await profileCheckingHandler('s-other-subject');

  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown) => {
    if (String(input).includes('/token')) {
      // The attacker's own account at the configured provider, with the
      // victim's WebID in the claim: a misconfigured mapper, a group-wide
      // claim, or an administrator at the provider all produce this token.
      return new Response(JSON.stringify({
        id_token: idToken({
          iss: 'https://idp.example',
          aud: 'pod-client',
          sub: 'subject-mallory',
          webid: WEBID,
        }),
      }), { status: 200 });
    }
    return new Response(profileGranting('https://idp.example', SUBJECT), {
      status: 200,
      headers: { 'content-type': 'text/turtle' },
    });
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-other-subject', code: 'c' })),
      isFailure(403, /does not accept subject-mallory as its subject/u),
    );
  } finally {
    globalThis.fetch = original;
  }
});

test('refuses a grant that names the provider but no subject at all', async () => {
  await assertProfileRejected(
    's-no-subject',
    `<${WEBID}> <${TRUST_PREDICATE}> [ <${GRANT_ISSUER_PREDICATE}> <https://idp.example> ] .`,
    403,
    /does not accept .* as its subject/u,
  );
});

// A subject stated as an IRI is a different claim about a different kind of
// thing, and coercing it to its string form would make it match.
test('refuses a grant whose subject is an IRI rather than a literal', async () => {
  await assertProfileRejected(
    's-subject-iri',
    `<${WEBID}> <${TRUST_PREDICATE}> [
       <${GRANT_ISSUER_PREDICATE}> <https://idp.example> ;
       <${GRANT_SUBJECT_PREDICATE}> <${SUBJECT}>
     ] .`,
    403,
    /does not accept .* as its subject/u,
  );
});

// Two grants in one profile must not combine: the subject that belongs to one
// provider says nothing about the other.
test('refuses a subject that belongs to a grant for another provider', async () => {
  await assertProfileRejected(
    's-crossed-grants',
    `${profileGranting('https://idp.example', 'subject-here')}
     ${profileGranting('https://other-idp.example', SUBJECT)}`,
    403,
    /does not accept .* as its subject/u,
  );
});

// The statement has to be about this WebID, not merely present in the document
// it resolves to. Everything below leaves the issuer IRI in the body, so an
// implementation that only searches the text accepts all of them.
test('refuses a grant made about a different subject', async () => {
  await assertProfileRejected(
    's-subject',
    `<https://pod.example/mallory/profile/card#me> <${TRUST_PREDICATE}> [
       <${GRANT_ISSUER_PREDICATE}> <https://idp.example> ;
       <${GRANT_SUBJECT_PREDICATE}> "${SUBJECT}"
     ] .`,
    403,
    /does not accept authentication/u,
  );
});

test('refuses a grant made with a different predicate', async () => {
  await assertProfileRejected(
    's-predicate',
    `<${WEBID}> <https://example.org/ns#mentions> [
       <${GRANT_ISSUER_PREDICATE}> <https://idp.example> ;
       <${GRANT_SUBJECT_PREDICATE}> "${SUBJECT}"
     ] .`,
    403,
    /does not accept authentication/u,
  );
});

test('refuses a grant whose issuer is a literal', async () => {
  await assertProfileRejected(
    's-literal',
    `<${WEBID}> <${TRUST_PREDICATE}> [
       <${GRANT_ISSUER_PREDICATE}> "https://idp.example" ;
       <${GRANT_SUBJECT_PREDICATE}> "${SUBJECT}"
     ] .`,
    403,
    /does not accept authentication/u,
  );
});

test('refuses a grant parked in a named graph', async () => {
  await assertProfileRejected(
    's-graph',
    `<https://pod.example/alice/other> { ${profileGranting('https://idp.example')} }`,
    403,
    /does not accept authentication/u,
  );
});

test('refuses a profile that is not served as Turtle', async () => {
  await assertProfileRejected(
    's-content-type',
    {
      body: JSON.stringify({ '@id': WEBID, [TRUST_PREDICATE]: { '@id': 'https://idp.example' }}),
      contentType: 'application/ld+json',
    },
    502,
    /not as text\/turtle/u,
  );
});

test('refuses a profile served without a media type', async () => {
  await assertProfileRejected(
    's-no-content-type',
    { body: profileGranting('https://idp.example'), contentType: null },
    502,
    /no media type/u,
  );
});

// A host that will not serve the document at all is the clearest case of the
// two the profile fetch has to tell apart: nothing about it is a statement on
// this login, and nobody at a browser can make it answer.
test('reports a profile host that answers with a status as its failure', async () => {
  for (const [ index, status ] of [ 404, 401, 500, 503 ].entries()) {
    await assertProfileRejected(
      `s-profile-status-${index}`,
      { status, contentType: null },
      502,
      new RegExp(`answered with ${status}`, 'u'),
    );
  }
});

test('reports a profile host that cannot be reached as its failure', async () => {
  const handler = await profileCheckingHandler('s-profile-unreachable');

  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown) => {
    if (String(input).includes('/token')) {
      return new Response(JSON.stringify({
        id_token: idToken({ iss: 'https://idp.example', aud: 'pod-client', sub: SUBJECT, webid: WEBID }),
      }), { status: 200 });
    }
    throw new TypeError('fetch failed');
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-profile-unreachable', code: 'c' })),
      isFailure(502, /could not be reached/u),
    );
  } finally {
    globalThis.fetch = original;
  }
});

test('refuses a profile that redirects to another document', async () => {
  await assertProfileRejected(
    's-redirect',
    { status: 302, location: 'https://elsewhere.example/card', contentType: null },
    502,
    /redirects elsewhere/u,
  );
});

test('refuses a profile whose body is not parseable', async () => {
  await assertProfileRejected('s-broken', '<not> <turtle', 502, /could not be parsed/u);
});

// The predicate is configurable, so a deployment can use a term of its own.
test('honours a configured trust predicate', async () => {
  const predicate = 'https://example.org/ns#acceptsLoginFrom';
  const handler = await profileCheckingHandler('s-predicate-ok', predicate);

  await withProfile(profileGranting('https://idp.example', SUBJECT, predicate), async () => {
    const { json } = await handler.login(callback({ state: 's-predicate-ok', code: 'c' }));
    assert.equal(json.accountId, 'acc-1');
  });
});

test('refuses the default predicate when another one is configured', async () => {
  await assertProfileRejected(
    's-predicate-mismatch',
    profileGranting('https://idp.example'),
    403,
    /does not accept authentication/u,
    'https://example.org/ns#acceptsLoginFrom',
  );
});

// A profile that never answers holds a worker for as long as it likes, and one
// that never stops holds its memory. The stub below stands in for both.

// The stub does not answer at all, and the deadline is what ends the wait —
// so the assertion is on how long the wait lasts, not merely on a signal
// having been handed over. A deadline of an hour holds a worker for an hour.
test('gives up on a profile that does not answer', { timeout: BEYOND_PATIENCE_MS }, async () => {
  const handler = await profileCheckingHandler('s-timeout');

  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown, init?: { signal?: AbortSignal }) => {
    if (String(input).includes('/token')) {
      return new Response(JSON.stringify({
        id_token: idToken({ iss: 'https://idp.example', aud: 'pod-client', sub: SUBJECT, webid: WEBID }),
      }), { status: 200 });
    }
    return neverAnswers(init);
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-timeout', code: 'c' })),
      isFailure(504, /did not answer within/u),
    );
  } finally {
    globalThis.fetch = original;
  }
});

// The token endpoint is a host this server waits on just as much as it waits
// on a profile, and a single worker is a single worker either way.
test('gives up on a token endpoint that does not answer', { timeout: BEYOND_PATIENCE_MS }, async () => {
  const handler = await exchangingHandler('s-token-timeout');

  const original = globalThis.fetch;
  globalThis.fetch = (async (_input: unknown, init?: { signal?: AbortSignal }) =>
    neverAnswers(init)) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-token-timeout', code: 'c' })),
      (error: unknown): boolean => statusOf(error) === 504 && /did not answer within/u.test(String(error)),
    );
  } finally {
    globalThis.fetch = original;
  }
});

test('gives up on a token endpoint that keeps sending', { timeout: DEADLINE_BOUND_MS }, async () => {
  const handler = await exchangingHandler('s-token-huge');

  const original = globalThis.fetch;
  globalThis.fetch = (async () => endlessBody('application/json')) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-token-huge', code: 'c' })),
      (error: unknown): boolean => statusOf(error) === 502 && /is larger than/u.test(String(error)),
    );
  } finally {
    globalThis.fetch = original;
  }
});

// Nothing about the exchange is the caller's doing: the endpoint is the one
// discovery named and the request carries this server's own credentials. A
// host that is down is not a bad callback, and reporting it as one hides the
// only failure an operator can act on among the many that really are the
// caller's.
test('blames the provider, not the caller, for a token endpoint it cannot reach', async () => {
  const handler = await exchangingHandler('s-token-unreachable');

  const original = globalThis.fetch;
  globalThis.fetch = (async () => {
    throw new TypeError('fetch failed');
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-token-unreachable', code: 'c' })),
      (error: unknown): boolean => statusOf(error) === 502 && /could not be reached/u.test(String(error)),
    );
  } finally {
    globalThis.fetch = original;
  }
});

// The line between the two: what the endpoint says about the code, the
// verifier and the redirect URI it was handed is a verdict on the callback
// this caller brought — a code already spent or expired ends here — so it
// stays the caller's failure.
test('still blames the caller for what the token endpoint says about their code', async () => {
  const handler = await exchangingHandler('s-token-rejected');

  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 })
  ) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-token-rejected', code: 'c' })),
      (error: unknown): boolean => isBadRequest(error) && /failed with 400/u.test(String(error)),
    );
  } finally {
    globalThis.fetch = original;
  }
});

/** Runs one exchange against a token endpoint that refuses it, and reports how. */
const refusedExchange = async (
  state: string,
  status: number,
  body: string | null,
): Promise<{ status?: number; message: string }> => {
  const handler = await exchangingHandler(state);

  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response(body, { status })) as unknown as typeof fetch;
  try {
    await handler.login(callback({ state, code: 'c' }));
    throw new Error(`the exchange was not refused at all for ${status}`);
  } catch (error) {
    return { status: statusOf(error), message: String(error) };
  } finally {
    globalThis.fetch = original;
  }
};

/**
 * The measured mapping, one row per answer a token endpoint can refuse with.
 * RFC 6749 §5.2 makes only a 400 or a 401 carrying a JSON object with an
 * `error` member a statement about the exchange at all, and of the codes such
 * a statement can carry only `invalid_grant` is about what this caller
 * brought. `invalid_client` is the client secret of this server being wrong,
 * which the person logging in cannot act on and would never see reported as
 * the provider's if it arrived as a bad request.
 */
const EXCHANGE_REFUSALS: { status: number; body: string | null; expected: number; why: string }[] = [
  { status: 400, body: '{"error":"invalid_grant"}', expected: 400, why: 'the code this caller brought' },
  { status: 401, body: '{"error":"invalid_grant"}', expected: 400, why: 'the code this caller brought' },
  { status: 400, body: '{"error":"invalid_client"}', expected: 502, why: 'this server\'s own credentials' },
  { status: 401, body: '{"error":"invalid_client"}', expected: 502, why: 'this server\'s own credentials' },
  { status: 400, body: '{"error":"invalid_scope"}', expected: 502, why: 'this server\'s own request' },
  { status: 400, body: null, expected: 502, why: 'a status without a statement' },
  { status: 401, body: null, expected: 502, why: 'a status without a statement' },
  { status: 400, body: '<html>no</html>', expected: 502, why: 'a status without a statement' },
  { status: 400, body: '{"error":42}', expected: 502, why: 'a status without a statement' },
  { status: 429, body: '{"error":"invalid_grant"}', expected: 502, why: 'a provider refusing to answer now' },
  { status: 429, body: null, expected: 502, why: 'a provider refusing to answer now' },
  { status: 500, body: '{"error":"invalid_grant"}', expected: 502, why: 'a provider that failed' },
  { status: 500, body: null, expected: 502, why: 'a provider that failed' },
  { status: 503, body: '{"error":"invalid_grant"}', expected: 502, why: 'a provider that is not there' },
  { status: 503, body: null, expected: 502, why: 'a provider that is not there' },
];

test('reports every refusal of the token endpoint as whose failure it is', async () => {
  for (const [ index, row ] of EXCHANGE_REFUSALS.entries()) {
    const { status, message } = await refusedExchange(`s-refusal-${index}`, row.status, row.body);
    assert.equal(
      status,
      row.expected,
      `${row.status} with ${row.body ?? 'no body'} was reported as ${status}, not as ${row.expected} ` +
      `(${row.why}) — the message was: ${message}`,
    );
  }
});

// The one this matters most for. A wrong client secret is a deployment that
// was never finished, and the person at the browser has no part in it and
// nothing to do about it; told as their bad request it is also the failure an
// operator is least likely to find, because it arrives among every genuinely
// bad callback the route refuses all day.
test('does not report this server\'s own credentials as the caller\'s mistake', async () => {
  const { status, message } = await refusedExchange(
    's-token-client-secret',
    401,
    '{"error":"invalid_client","error_description":"client authentication failed"}',
  );

  assert.equal(status, 502, `a refused client secret was reported to the caller as ${status}`);
  assert.match(message, /refused the exchange with 401 \(invalid_client\)/u);
});

// The error code is a string the provider chooses that ends up in a message
// handed back to whoever called and in a line this server logs. RFC 6749 §A.7
// says what a code may be made of; what is not a code is not repeated as one,
// and a value that is too long is refused rather than cut down to size, since
// a code cut down to size is a different code.
test('does not hand back a provider string that is no error code', async () => {
  const { status, message } = await refusedExchange(
    's-token-error-oversized',
    400,
    JSON.stringify({ error: 'e'.repeat(200000) }),
  );

  assert.equal(status, 502, 'a string that is no error code was read as a verdict on the caller');
  assert.ok(!/eeeeeeee/u.test(message), 'the message repeats a string the provider chose');
  assert.ok(message.length < 200, `the message the provider dictated is ${message.length} characters long`);
});

// A line break in a code the provider chose is a line in this server's log
// that the provider wrote, and a log line nobody wrote is a log line nobody
// can trust.
test('does not let an error code carry a line of its own into the log', async () => {
  const { status, message } = await refusedExchange(
    's-token-error-newline',
    400,
    JSON.stringify({ error: 'invalid_grant\nWARN fake log line' }),
  );

  assert.equal(status, 502, 'a string that is no error code was read as a verdict on the caller');
  assert.ok(!message.includes('\n'), 'the message carries a line break the provider chose');
  assert.ok(!/WARN/u.test(message), 'the message carries a line the provider wrote');
});

// A refusal whose body never finishes is a wait, not a verdict. The deadline
// is what ends it, and the status that says "waited and got nothing" is the
// one an operator can tell apart at a glance — folded into the refusal, it
// reads as the provider having judged this callback, which it never did.
test('gives up on a refusal that stops mid-body', { timeout: BEYOND_PATIENCE_MS }, async () => {
  const handler = await exchangingHandler('s-refusal-stalls');

  const original = globalThis.fetch;
  globalThis.fetch = (async (_input: unknown, init?: { signal?: AbortSignal }) => {
    // The status arrives, the statement that would give it meaning does not.
    const stalling = stallsMidBody('application/json', init);
    return new Response(stalling.body, { status: 400 });
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-refusal-stalls', code: 'c' })),
      (error: unknown): boolean => statusOf(error) === 504 && /did not answer within/u.test(String(error)),
    );
  } finally {
    globalThis.fetch = original;
  }
});

// The deadline has to cover the answer, not just its first byte. A provider
// that sends headers and then stops holds a worker exactly as long as one that
// never answers at all, and the exception that ends the read is not one of this
// server's own — unmapped it surfaces as an internal fault for something that
// happened at the provider's end.
test('gives up on a token endpoint that stops mid-answer', { timeout: BEYOND_PATIENCE_MS }, async () => {
  const handler = await exchangingHandler('s-token-stalls');

  const original = globalThis.fetch;
  globalThis.fetch = (async (_input: unknown, init?: { signal?: AbortSignal }) =>
    stallsMidBody('application/json', init)) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-token-stalls', code: 'c' })),
      (error: unknown): boolean => statusOf(error) === 504 && /did not answer within/u.test(String(error)),
    );
  } finally {
    globalThis.fetch = original;
  }
});

// The body never ends, so only an implementation that counts as it reads ever
// returns from here. One that buffers the whole body and looks at its size
// afterwards runs until this test gives up on it.
test('gives up on a profile that keeps sending', { timeout: DEADLINE_BOUND_MS }, async () => {
  const handler = await profileCheckingHandler('s-huge');

  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown) => {
    if (String(input).includes('/token')) {
      return new Response(JSON.stringify({
        id_token: idToken({ iss: 'https://idp.example', aud: 'pod-client', sub: SUBJECT, webid: WEBID }),
      }), { status: 200 });
    }
    return endlessBody('text/turtle');
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      handler.login(callback({ state: 's-huge', code: 'c' })),
      isFailure(502, /is larger than/u),
    );
  } finally {
    globalThis.fetch = original;
  }
});

// The server writes `remember` as a setting on the account, not on the session,
// so naming it here re-decides it for every session that account already has —
// including password logins that chose not to be remembered.
test('leaves the account\'s remember setting alone', async () => {
  const { handler, store, settings } = makeHandler(
    { webid: WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
  );
  await start(store, 's-remember');

  const { json } = await handler.login(callback({ state: 's-remember', code: 'c' }));
  assert.equal('remember' in json, false);

  // And once more through the server's own login resolution, which is what
  // would write the setting.
  await start(store, 's-remember-2');
  await handler.handle(callback({ state: 's-remember-2', code: 'c' }));
  assert.deepEqual(settings, []);
});

test('clears the pending-login cookie once the login is redeemed', async () => {
  const { handler, store } = makeHandler(
    { webid: WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
  );
  await start(store, 's-clear');

  const { metadata } = await handler.login(callback({ state: 's-clear', code: 'c' }));
  const header = metadata?.get(namedNode(setCookiePredicate))?.value;
  assert.match(String(header), /Max-Age=0/u);
});

// Everything a caller sends is a shape they chose, including the shapes this
// server did not think to expect. A body that is not an object and a cookie
// jar holding two of the one cookie both used to leave this handler as an
// exception of its own — a fault of this server reported for input somebody
// else picked, which is the mirror image of blaming a caller for the provider.

test('reports a callback body that is no object as the caller\'s', async () => {
  const { handler, store } = makeHandler({ webid: WEBID, sub: SUBJECT }, []);
  await start(store, 's-body');

  for (const body of [ null, undefined, 'a string', 5, [], true ]) {
    await assert.rejects(
      handler.login(callback(body)),
      isFailure(400, /Callback carried no/u),
      `a body of ${JSON.stringify(body) ?? 'undefined'} was not answered as the caller's`,
    );
    assert.ok(await store.peek('s-body'), 'a body that is no object spent the login');
  }
});

// The same for a state or a code that is present but is not a string: a JSON
// body carries whatever types its author put in it.
test('reports a state or code that is no string as the caller\'s', async () => {
  const { handler, store } = makeHandler({ webid: WEBID, sub: SUBJECT }, []);
  await start(store, 's-types');

  for (const json of [
    { state: 5, code: 'c' }, { state: {}, code: 'c' }, { state: '', code: 'c' },
    { state: 's-types', code: 5 }, { state: 's-types', code: '' },
  ]) {
    await assert.rejects(
      handler.login(callback(json)),
      isFailure(400, /Callback carried no (state|code)/u),
      `${JSON.stringify(json)} was not answered as the caller's`,
    );
  }
});

// A browser can be made to hold two cookies of one name — a sibling host that
// once wrote one without the prefix, or a jar the person edited themselves.
// Which of them belongs to this login is not knowable here.
test('reports a browser holding several pending-login cookies as the caller\'s', async () => {
  const { handler, store } = makeHandler(
    { webid: WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
  );
  await start(store, 's-two-cookies');

  const metadata = new RepresentationMetadata(TARGET);
  metadata.add(namedNode(cookiePredicate), HANDLE);
  metadata.add(namedNode(cookiePredicate), 'a-second-handle');
  const input = { method: 'POST', target: TARGET, json: { state: 's-two-cookies', code: 'c' }, metadata };

  await assert.rejects(handler.login(input as never), isFailure(400, /2 __Host-.* cookies/u));
  // And the login it named is untouched, so the browser that started it can
  // still finish it once its jar holds one cookie again.
  assert.ok(await store.peek('s-two-cookies'), 'a second cookie spent the login');
});

// Same exposure as the start route: a GET that prefers no particular type gets
// past the HTML view and reaches this handler. And as there, GET is only the
// method that arrives by accident — POST is the only one this route answers,
// so anything else is refused as well.
test('completes a login on a POST and on nothing else', async () => {
  const { handler, store } = makeHandler(
    { webid: WEBID, sub: SUBJECT },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }],
  );
  await start(store, 's-method');

  const isMethodNotAllowed = (error: unknown): boolean =>
    (error as { statusCode?: number }).statusCode === 405;

  for (const method of ['GET', 'HEAD', 'PUT', 'DELETE', 'PATCH']) {
    const metadata = new RepresentationMetadata(TARGET);
    metadata.add(namedNode(cookiePredicate), HANDLE);
    const other = { method, target: TARGET, json: { state: 's-method', code: 'c' }, metadata } as never;

    await assert.rejects(handler.handleSafe(other), isMethodNotAllowed, `${method} was not refused`);
    await assert.rejects(handler.login(other), isMethodNotAllowed, `${method} was not refused`);
    // The login it named is untouched, so the browser that started it can
    // still finish it.
    assert.ok(await store.peek('s-method'), `a ${method} spent the login`);
  }

  const { json } = await handler.login(callback({ state: 's-method', code: 'c' }));
  assert.equal(json.accountId, 'acc-1');
});
