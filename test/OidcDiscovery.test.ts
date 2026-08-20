import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OidcDiscovery } from '../src/OidcDiscovery.ts';
import {
  BEYOND_PATIENCE_MS, DEADLINE_BOUND_MS, endlessBody, neverAnswers, stallsMidBody,
} from './bounds.ts';

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

// Discovery is the first thing a login touches, and it waits on a host this
// server does not control just as the profile fetch does.
test('gives up on an issuer that does not answer', { timeout: BEYOND_PATIENCE_MS }, async () => {
  const impl = (async (_input: unknown, init?: { signal?: AbortSignal }) =>
    neverAnswers(init)) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(discovery.endpoints(), /did not answer within/u);
  });
});

test('gives up on a discovery document that keeps sending', { timeout: DEADLINE_BOUND_MS }, async () => {
  const impl = (async () => endlessBody('application/json')) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(discovery.endpoints(), /is larger than/u);
  });
});

const statusOf = (error: unknown): number | undefined => (error as { statusCode?: number }).statusCode;

// Discovery reads nothing a caller sent: the issuer is configuration and the
// document is the provider's. So a refusal here is the provider's failure and
// says so with a status of its own, rather than blaming the request or being
// filed as a fault of this server.
test('blames the provider, not the caller, for a discovery document it will not accept', async () => {
  const impl = (async () => new Response('nope', { status: 404 })) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(discovery.endpoints(), (error: unknown): boolean => statusOf(error) === 502);
  });
});

test('blames the provider for a document that is not the JSON it has to be', async () => {
  const impl = (async () => new Response('<html>', { status: 200 })) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(discovery.endpoints(), (error: unknown): boolean => statusOf(error) === 502);
  });
});

// A provider that never answers is a different failure from one that answered
// badly, and the only one an operator can act on without reading a log.
test('reports an issuer that does not answer as a timeout of its own', async () => {
  const impl = (async () => {
    const error = new Error('timed out');
    error.name = 'TimeoutError';
    throw error;
  }) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(discovery.endpoints(), (error: unknown): boolean => statusOf(error) === 504);
  });
});

// The deadline covers the document, not merely the headers that announce it.
// An issuer that answers and then stops holds a worker just as long as one that
// never answers, and what ends that read is not an error of this server's own —
// left unmapped it would be reported as an internal fault of this server.
test('gives up on an issuer that stops mid-document', { timeout: BEYOND_PATIENCE_MS }, async () => {
  const impl = (async (_input: unknown, init?: { signal?: AbortSignal }) =>
    stallsMidBody('application/json', init)) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('https://idp.example');
    await assert.rejects(
      discovery.endpoints(),
      (error: unknown): boolean => statusOf(error) === 504 && /did not answer within/u.test(String(error)),
    );
  });
});

// An endpoint that is a string but no URL is a document that cannot be acted
// on, and the authorization one is handed straight to `new URL` where the
// login is built — unchecked here it surfaces there as an unclassified fault
// of this server for a document the provider wrote.
test('refuses a document whose endpoints are not URLs', async () => {
  for (const endpoint of [ 'authorization_endpoint', 'token_endpoint' ]) {
    const impl = (async () =>
      new Response(document({ [endpoint]: 'not a url' }), { status: 200 })
    ) as unknown as typeof fetch;

    await withFetch(impl, async () => {
      const discovery = new OidcDiscovery('https://idp.example');
      await assert.rejects(discovery.endpoints(), (error: unknown): boolean => {
        assert.equal(statusOf(error), 502, `a ${endpoint} that is no URL was reported as ${statusOf(error)}`);
        assert.match(String(error), new RegExp(`${endpoint} that is not an absolute URL`, 'u'));
        return true;
      });
    });
  }
});

// The issuer is configuration. An issuer that is no URL is this deployment's
// own failure, and left to `new URL` it is a fault that names neither the
// setting nor its value.
test('reports a configured issuer that is no URL as this server\'s own', async () => {
  const impl = (async () => new Response(document(), { status: 200 })) as unknown as typeof fetch;

  await withFetch(impl, async () => {
    const discovery = new OidcDiscovery('not an issuer');
    await assert.rejects(discovery.endpoints(), (error: unknown): boolean => {
      assert.equal(statusOf(error), 500, `a configured issuer that is no URL was reported as ${statusOf(error)}`);
      assert.match(String(error), /configured issuer not an issuer is not an absolute URL/u);
      return true;
    });
  });
});
