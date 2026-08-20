import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OidcDiscovery } from '../src/OidcDiscovery.ts';

const withFetch = async (impl: typeof fetch, fn: () => Promise<void>): Promise<void> => {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  try {
    await fn();
  } finally {
    globalThis.fetch = original;
  }
};

const document = (extra: Record<string, unknown> = {}): string => JSON.stringify({
  issuer: 'https://idp.example',
  authorization_endpoint: 'https://idp.example/authorize',
  token_endpoint: 'https://idp.example/api/oidc/token',
  ...extra,
});

test('reads both endpoints from the discovery document', async () => {
  let calls = 0;
  const impl = (async () => {
    calls += 1;
    return new Response(document(), { status: 200 });
  }) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    assert.deepEqual(await discovery.endpoints(), {
      authorization: 'https://idp.example/authorize',
      token: 'https://idp.example/api/oidc/token',
    });
    // Cached: a second call must not hit the network again.
    await discovery.endpoints();
    assert.equal(calls, 1);
  });
});

test('ignores trailing slashes when comparing the issuer it was given', async () => {
  const impl = (async () =>
    new Response(document({ issuer: 'https://idp.example/' }), { status: 200 })
  ) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    assert.equal((await discovery.endpoints()).token, 'https://idp.example/api/oidc/token');
  });
});

// Every later check hangs off this document, so a document that says it belongs
// to somebody else describes somebody else's provider.
test('refuses a document that names another issuer', async () => {
  const impl = (async () =>
    new Response(document({ issuer: 'https://evil.example' }), { status: 200 })
  ) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(discovery.endpoints(), /names https:\/\/evil\.example as its issuer/u);
  });
});

test('refuses a document that carries no issuer', async () => {
  const impl = (async () =>
    new Response(JSON.stringify({
      authorization_endpoint: 'https://idp.example/authorize',
      token_endpoint: 'https://idp.example/token',
    }), { status: 200 })
  ) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(discovery.endpoints(), /carried no issuer/u);
  });
});

// The stub follows unless asked not to, so an implementation that leaves the
// default in place silently reads its endpoints off another host.
test('refuses to follow a redirect away from the issuer', async () => {
  const impl = (async (input: unknown, init?: { redirect?: string }) => {
    if (String(input).includes('elsewhere.example')) {
      return new Response(document({ issuer: 'https://idp.example' }), { status: 200 });
    }
    if (init?.redirect === 'manual') {
      return new Response(null, { status: 302, headers: { location: 'https://elsewhere.example/config' }});
    }
    return new Response(document({ issuer: 'https://idp.example' }), { status: 200 });
  }) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(discovery.endpoints(), /redirects elsewhere/u);
  });
});

test('fails loudly when the document is missing an endpoint', async () => {
  const impl = (async () =>
    new Response(JSON.stringify({
      issuer: 'https://idp.example',
      authorization_endpoint: 'https://idp.example/authorize',
    }), { status: 200 })
  ) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(discovery.endpoints(), /token_endpoint/u);
  });
});

test('fails loudly when discovery is unreachable', async () => {
  const impl = (async () => new Response('nope', { status: 404 })) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(discovery.endpoints(), /404/u);
  });
});
