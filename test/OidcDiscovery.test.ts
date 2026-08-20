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

test('reads both endpoints from the discovery document', async () => {
  let calls = 0;
  const impl = (async () => {
    calls += 1;
    return new Response(JSON.stringify({
      authorization_endpoint: 'https://idp.example/authorize',
      token_endpoint: 'https://idp.example/api/oidc/token',
    }), { status: 200 });
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

test('fails loudly when the document is missing an endpoint', async () => {
  const impl = (async () =>
    new Response(JSON.stringify({ authorization_endpoint: 'https://idp.example/authorize' }), { status: 200 })
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
