import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OidcCallbackHandler } from '../src/OidcCallbackHandler.ts';
import { PendingLoginStore } from '../src/PendingLoginStore.ts';

const WEBID = 'https://pod.example/alice/profile/card#me';

const makeHandler = (claims: Record<string, unknown>, links: unknown[], webIdClaim?: string) => {
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
  });
  // Neither the provider nor the profile fetch is under test in these cases;
  // each has its own tests below.
  (handler as unknown as { exchange: unknown }).exchange = async () => claims;
  (handler as unknown as { assertProfileTrustsIssuer: unknown }).assertProfileTrustsIssuer = async () => undefined;
  return { handler, store, calls };
};

const profileTrusting = (issuer: string): string => `
  <${WEBID}> <https://tophcodes.github.io/css-oidc-login/ns#loginIssuer> <${issuer}> .
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

test('rejects an unknown or replayed state', async () => {
  const { handler } = makeHandler({ webid: WEBID }, []);
  await assert.rejects(handler.login({ json: { state: 'never-issued', code: 'c' }} as never), /state/u);
});

test('rejects a callback with no code', async () => {
  const { handler, store } = makeHandler({ webid: WEBID }, []);
  await store.create('s5', { codeVerifier: 'v' });

  await assert.rejects(handler.login({ json: { state: 's5' }} as never), /code/u);
});

// The next two exercise the real exchange path, because the checks they cover
// live there. OIDC Core 3.1.3.7 requires both even when the signature is not
// re-verified.

const idToken = (claims: Record<string, unknown>): string =>
  `header.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`;

const withTokenResponse = async (claims: Record<string, unknown>, fn: () => Promise<void>): Promise<void> => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ id_token: idToken(claims) }), { status: 200 })
  ) as unknown as typeof fetch;
  try {
    await fn();
  } finally {
    globalThis.fetch = original;
  }
};

test('rejects a token issued by a different provider', async () => {
  const { handler, store } = makeHandler({}, [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }]);
  delete (handler as unknown as { exchange?: unknown }).exchange;
  await store.create('s6', { codeVerifier: 'v' });

  await withTokenResponse(
    { iss: 'https://evil.example', aud: 'pod-client', webid: WEBID },
    async () => {
      await assert.rejects(handler.login({ json: { state: 's6', code: 'c' }} as never), /not by https:\/\/idp\.example/u);
    },
  );
});

test('rejects a token issued for a different client of the same provider', async () => {
  const { handler, store } = makeHandler({}, [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }]);
  delete (handler as unknown as { exchange?: unknown }).exchange;
  await store.create('s7', { codeVerifier: 'v' });

  await withTokenResponse(
    { iss: 'https://idp.example', aud: 'some-other-client', webid: WEBID },
    async () => {
      await assert.rejects(handler.login({ json: { state: 's7', code: 'c' }} as never), /different client/u);
    },
  );
});

// The per-account opt-in. These two run the real profile check.

const withProfile = async (turtle: string, fn: () => Promise<void>): Promise<void> => {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown) => {
    if (String(input).includes('/token')) {
      return new Response(JSON.stringify({
        id_token: idToken({ iss: 'https://idp.example', aud: 'pod-client', webid: WEBID }),
      }), { status: 200 });
    }
    return new Response(turtle, { status: 200, headers: { 'content-type': 'text/turtle' }});
  }) as unknown as typeof fetch;
  try {
    await fn();
  } finally {
    globalThis.fetch = original;
  }
};

test('refuses a valid token when the profile does not name the provider', async () => {
  const { handler, store } = makeHandler({}, [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }]);
  delete (handler as unknown as { exchange?: unknown }).exchange;
  delete (handler as unknown as { assertProfileTrustsIssuer?: unknown }).assertProfileTrustsIssuer;
  await store.create('s9', { codeVerifier: 'v' });

  await withProfile(profileTrusting('https://other-idp.example'), async () => {
    await assert.rejects(
      handler.login({ json: { state: 's9', code: 'c' }} as never),
      /does not accept authentication/u,
    );
  });
});

test('accepts when the profile names the provider', async () => {
  const { handler, store } = makeHandler({}, [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }]);
  delete (handler as unknown as { exchange?: unknown }).exchange;
  delete (handler as unknown as { assertProfileTrustsIssuer?: unknown }).assertProfileTrustsIssuer;
  await store.create('s10', { codeVerifier: 'v' });

  await withProfile(profileTrusting('https://idp.example'), async () => {
    const { json } = await handler.login({ json: { state: 's10', code: 'c' }} as never);
    assert.equal(json.accountId, 'acc-1');
  });
});

test('accepts a token whose aud is an array containing our client', async () => {
  const { handler, store } = makeHandler({}, [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }]);
  delete (handler as unknown as { exchange?: unknown }).exchange;
  await store.create('s8', { codeVerifier: 'v' });

  await withTokenResponse(
    { iss: 'https://idp.example/', aud: ['pod-client', 'other'], webid: WEBID },
    async () => {
      const { json } = await handler.login({ json: { state: 's8', code: 'c' }} as never);
      assert.equal(json.accountId, 'acc-1');
    },
  );
});
