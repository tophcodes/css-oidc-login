import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OidcCallbackHandler } from '../src/OidcCallbackHandler.ts';
import { PendingLoginStore } from '../src/PendingLoginStore.ts';

const WEBID = 'https://pod.example/alice/profile/card#me';
const TRUST_PREDICATE = 'https://tophcodes.github.io/css-oidc-login/ns#loginIssuer';

const makeHandler = (
  claims: Record<string, unknown>,
  links: unknown[],
  webIdClaim?: string,
  trustPredicate?: string,
) => {
  const store = new PendingLoginStore();
  const calls: unknown[][] = [];
  const handler = new OidcCallbackHandler({
    accountStore: {} as never,
    cookieStore: {} as never,
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
  (handler as unknown as { assertProfileTrustsIssuer: unknown }).assertProfileTrustsIssuer = async () => undefined;
  return { handler, store, calls };
};

/** Drops the stubs so a test runs the real token exchange and profile check. */
const unstub = (handler: OidcCallbackHandler, ...names: string[]): void => {
  for (const name of names) {
    delete (handler as unknown as Record<string, unknown>)[name];
  }
};

const isBadRequest = (error: unknown): boolean =>
  (error as { statusCode?: number }).statusCode === 400;

const profileTrusting = (issuer: string, predicate = TRUST_PREDICATE): string => `
  <${WEBID}> <${predicate}> <${issuer}> .
`;

test('logs in the account linked to the WebID in the claim', async () => {
  const { handler, store, calls } = makeHandler({ webid: WEBID }, [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }]);
  await store.create('s1', { codeVerifier: 'v' });

  const { json } = await handler.login({ json: { state: 's1', code: 'c' }} as never);

  assert.equal(json.accountId, 'acc-1');
  assert.deepEqual(calls, [['webIdLink', { webId: WEBID }]]);
});

test('honours a custom claim name', async () => {
  const { handler, store } = makeHandler(
    { 'http://example.org/webid': WEBID },
    [{ id: 'l1', webId: WEBID, accountId: 'acc-2' }],
    'http://example.org/webid',
  );
  await store.create('s2', { codeVerifier: 'v' });

  const { json } = await handler.login({ json: { state: 's2', code: 'c' }} as never);
  assert.equal(json.accountId, 'acc-2');
});

test('rejects a token without the claim', async () => {
  const { handler, store } = makeHandler({ sub: 'abc' }, []);
  await store.create('s3', { codeVerifier: 'v' });

  await assert.rejects(handler.login({ json: { state: 's3', code: 'c' }} as never), /no webid claim/u);
});

test('rejects a WebID no account is linked to', async () => {
  const { handler, store } = makeHandler({ webid: 'https://elsewhere.example/#me' }, []);
  await store.create('s4', { codeVerifier: 'v' });

  await assert.rejects(handler.login({ json: { state: 's4', code: 'c' }} as never), /not linked/u);
});

// Which of several linked accounts was meant is not knowable from the token,
// and the storage does not promise an order, so there is nothing to pick from.
test('rejects a WebID that is linked to more than one account', async () => {
  const { handler, store } = makeHandler({ webid: WEBID }, [
    { id: 'l1', webId: WEBID, accountId: 'acc-1' },
    { id: 'l2', webId: WEBID, accountId: 'acc-2' },
  ]);
  await store.create('s-multi', { codeVerifier: 'v' });

  await assert.rejects(
    handler.login({ json: { state: 's-multi', code: 'c' }} as never),
    (error: unknown): boolean => isBadRequest(error) && /linked to 2 accounts/u.test(String(error)),
  );
});

test('rejects an unknown state', async () => {
  const { handler } = makeHandler({ webid: WEBID }, []);
  await assert.rejects(handler.login({ json: { state: 'never-issued', code: 'c' }} as never), /state/u);
});

test('rejects a state that was already used', async () => {
  const { handler, store } = makeHandler({ webid: WEBID }, [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }]);
  await store.create('s-replay', { codeVerifier: 'v' });

  const { json } = await handler.login({ json: { state: 's-replay', code: 'c' }} as never);
  assert.equal(json.accountId, 'acc-1');

  await assert.rejects(
    handler.login({ json: { state: 's-replay', code: 'c' }} as never),
    /Unknown or expired state/u,
  );
});

test('rejects a callback with no code', async () => {
  const { handler, store } = makeHandler({ webid: WEBID }, []);
  await store.create('s5', { codeVerifier: 'v' });

  await assert.rejects(handler.login({ json: { state: 's5' }} as never), /code/u);
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
  await store.create(state, { codeVerifier: 'v' });
  return handler;
};

test('rejects a token issued by a different provider', async () => {
  const handler = await exchangingHandler('s6');

  await withTokenResponse(
    { iss: 'https://evil.example', aud: 'pod-client', webid: WEBID },
    async () => {
      await assert.rejects(handler.login({ json: { state: 's6', code: 'c' }} as never), /not by https:\/\/idp\.example/u);
    },
  );
});

test('rejects a token issued for a different client of the same provider', async () => {
  const handler = await exchangingHandler('s7');

  await withTokenResponse(
    { iss: 'https://idp.example', aud: 'some-other-client', webid: WEBID },
    async () => {
      await assert.rejects(handler.login({ json: { state: 's7', code: 'c' }} as never), /different client/u);
    },
  );
});

test('rejects a token that carries no issuer', async () => {
  const handler = await exchangingHandler('s-no-iss');

  await withTokenResponse({ aud: 'pod-client', webid: WEBID }, async () => {
    await assert.rejects(
      handler.login({ json: { state: 's-no-iss', code: 'c' }} as never),
      (error: unknown): boolean => isBadRequest(error) && /no issuer/u.test(String(error)),
    );
  });
});

test('rejects a token that carries no audience', async () => {
  const handler = await exchangingHandler('s-no-aud');

  await withTokenResponse({ iss: 'https://idp.example', webid: WEBID }, async () => {
    await assert.rejects(
      handler.login({ json: { state: 's-no-aud', code: 'c' }} as never),
      (error: unknown): boolean => isBadRequest(error) && /no audience/u.test(String(error)),
    );
  });
});

test('rejects a token whose aud array does not contain our client', async () => {
  const handler = await exchangingHandler('s-foreign-aud');

  await withTokenResponse(
    { iss: 'https://idp.example', aud: ['other', 'yet-another'], azp: 'other', webid: WEBID },
    async () => {
      await assert.rejects(
        handler.login({ json: { state: 's-foreign-aud', code: 'c' }} as never),
        /different client/u,
      );
    },
  );
});

test('accepts a token whose aud is an array containing our client and whose azp names us', async () => {
  const handler = await exchangingHandler('s8');

  await withTokenResponse(
    { iss: 'https://idp.example/', aud: ['pod-client', 'other'], azp: 'pod-client', webid: WEBID },
    async () => {
      const { json } = await handler.login({ json: { state: 's8', code: 'c' }} as never);
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
    { iss: 'https://idp.example', aud: ['rogue-client', 'pod-client'], webid: WEBID },
    async () => {
      await assert.rejects(
        handler.login({ json: { state: 's-azp-missing', code: 'c' }} as never),
        (error: unknown): boolean => isBadRequest(error) && /authorized party/u.test(String(error)),
      );
    },
  );
});

test('rejects a multi-audience token whose azp names another client', async () => {
  const handler = await exchangingHandler('s-azp-wrong');

  await withTokenResponse(
    { iss: 'https://idp.example', aud: ['rogue-client', 'pod-client'], azp: 'rogue-client', webid: WEBID },
    async () => {
      await assert.rejects(
        handler.login({ json: { state: 's-azp-wrong', code: 'c' }} as never),
        /authorized party/u,
      );
    },
  );
});

test('rejects an ID token that is not a JWT', async () => {
  const handler = await exchangingHandler('s-malformed');

  await withTokenBody({ id_token: 'not-a-jwt' }, async () => {
    await assert.rejects(
      handler.login({ json: { state: 's-malformed', code: 'c' }} as never),
      (error: unknown): boolean => isBadRequest(error) && /well-formed JWT/u.test(String(error)),
    );
  });
});

test('rejects an ID token whose payload is not JSON', async () => {
  const handler = await exchangingHandler('s-garbage');

  await withTokenBody({ id_token: `header.${Buffer.from('not json').toString('base64url')}.signature` }, async () => {
    await assert.rejects(
      handler.login({ json: { state: 's-garbage', code: 'c' }} as never),
      (error: unknown): boolean => isBadRequest(error) && /not valid JSON/u.test(String(error)),
    );
  });
});

// The per-account opt-in. These run the real profile check.

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

  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown) => {
    if (String(input).includes('/token')) {
      return new Response(JSON.stringify({
        id_token: idToken({ iss: 'https://idp.example', aud: 'pod-client', webid: WEBID }),
      }), { status: 200 });
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
  unstub(handler, 'exchange', 'assertProfileTrustsIssuer');
  await store.create(state, { codeVerifier: 'v' });
  return handler;
};

const assertProfileRejected = async (
  state: string,
  profile: string | ProfileResponse,
  message: RegExp,
  trustPredicate?: string,
): Promise<void> => {
  const handler = await profileCheckingHandler(state, trustPredicate);
  await withProfile(profile, async () => {
    await assert.rejects(
      handler.login({ json: { state, code: 'c' }} as never),
      (error: unknown): boolean => isBadRequest(error) && message.test(String(error)),
    );
  });
};

test('refuses a valid token when the profile does not name the provider', async () => {
  await assertProfileRejected('s9', profileTrusting('https://other-idp.example'), /does not accept authentication/u);
});

test('accepts when the profile names the provider', async () => {
  const handler = await profileCheckingHandler('s10');

  await withProfile(profileTrusting('https://idp.example'), async () => {
    const { json } = await handler.login({ json: { state: 's10', code: 'c' }} as never);
    assert.equal(json.accountId, 'acc-1');
  });
});

// The statement has to be about this WebID, not merely present in the document
// it resolves to. Everything below leaves the issuer IRI in the body, so an
// implementation that only searches the text accepts all of them.
test('refuses a trust statement made about a different subject', async () => {
  await assertProfileRejected(
    's-subject',
    `<https://pod.example/mallory/profile/card#me> <${TRUST_PREDICATE}> <https://idp.example> .`,
    /does not accept authentication/u,
  );
});

test('refuses a trust statement made with a different predicate', async () => {
  await assertProfileRejected(
    's-predicate',
    `<${WEBID}> <https://example.org/ns#mentions> <https://idp.example> .`,
    /does not accept authentication/u,
  );
});

test('refuses a trust statement whose object is a literal', async () => {
  await assertProfileRejected(
    's-literal',
    `<${WEBID}> <${TRUST_PREDICATE}> "https://idp.example" .`,
    /does not accept authentication/u,
  );
});

test('refuses a trust statement parked in a named graph', async () => {
  await assertProfileRejected(
    's-graph',
    `<https://pod.example/alice/other> { <${WEBID}> <${TRUST_PREDICATE}> <https://idp.example> . }`,
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
    /not as text\/turtle/u,
  );
});

test('refuses a profile served without a media type', async () => {
  await assertProfileRejected(
    's-no-content-type',
    { body: profileTrusting('https://idp.example'), contentType: null },
    /no media type/u,
  );
});

test('refuses a profile that redirects to another document', async () => {
  await assertProfileRejected(
    's-redirect',
    { status: 302, location: 'https://elsewhere.example/card', contentType: null },
    /redirects elsewhere/u,
  );
});

test('refuses a profile whose body is not parseable', async () => {
  await assertProfileRejected('s-broken', '<not> <turtle', /could not be parsed/u);
});

// The predicate is configurable, so a deployment can use a term of its own.
test('honours a configured trust predicate', async () => {
  const predicate = 'https://example.org/ns#acceptsLoginFrom';
  const handler = await profileCheckingHandler('s-predicate-ok', predicate);

  await withProfile(profileTrusting('https://idp.example', predicate), async () => {
    const { json } = await handler.login({ json: { state: 's-predicate-ok', code: 'c' }} as never);
    assert.equal(json.accountId, 'acc-1');
  });
});

test('refuses the default predicate when another one is configured', async () => {
  await assertProfileRejected(
    's-predicate-mismatch',
    profileTrusting('https://idp.example'),
    /does not accept authentication/u,
    'https://example.org/ns#acceptsLoginFrom',
  );
});
