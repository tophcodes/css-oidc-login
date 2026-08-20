import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DataFactory } from 'n3';
import { OidcRedirectHandler } from '../src/OidcRedirectHandler.ts';
import { OidcDiscovery } from '../src/OidcDiscovery.ts';
import { PendingLoginStore } from '../src/PendingLoginStore.ts';

const { setCookiePredicate } = new PendingLoginStore();

const { namedNode } = DataFactory;

const discovery = {
  endpoints: async () => ({
    authorization: 'https://idp.example/authorize',
    token: 'https://idp.example/token',
  }),
};

const target = { path: 'https://pod.example/.account/login/oidc/' };
const input = { method: 'POST', target, json: {}, metadata: {}} as never;

test('builds an authorization URL with PKCE and the configured scopes', async () => {
  const store = new PendingLoginStore();
  const handler = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'https://pod.example/.account/login/oidc/callback/',
    scopes: 'openid profile',
  });

  const { json } = await handler.handle(input);
  const url = new URL(json.location as string);

  assert.equal(url.origin + url.pathname, 'https://idp.example/authorize');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('client_id'), 'pod-client');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://pod.example/.account/login/oidc/callback/');
  assert.equal(url.searchParams.get('scope'), 'openid profile');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');

  // Read the verifier once (consume is single-use) and reuse it for both checks below.
  const state = url.searchParams.get('state') as string;
  const pending = await store.consume(state);
  assert.ok(pending);

  const expectedChallenge = createHash('sha256').update(pending.codeVerifier).digest('base64url');
  assert.equal(url.searchParams.get('code_challenge'), expectedChallenge);

  // The state must be redeemable exactly once.
  assert.equal(await store.consume(state), undefined);
});

test('issues a different state and challenge on every call', async () => {
  const store = new PendingLoginStore();
  const handler = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'https://pod.example/cb',
    scopes: 'openid',
  });

  const first = new URL((await handler.handle(input)).json.location as string);
  const second = new URL((await handler.handle(input)).json.location as string);

  assert.notEqual(first.searchParams.get('state'), second.searchParams.get('state'));
  assert.notEqual(first.searchParams.get('code_challenge'), second.searchParams.get('code_challenge'));
});

// The handle is the browser's half of the login. It never travels through the
// provider, so it is not in the callback URL the way the state is.
test('hands the browser a handle that is not the state and not in the authorization URL', async () => {
  const store = new PendingLoginStore();
  const handler = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'https://pod.example/.account/login/oidc/callback/',
  });

  const { json, metadata } = await handler.handle(input);
  const cookie = metadata?.get(namedNode(setCookiePredicate))?.value;
  assert.ok(cookie, 'no pending-login cookie was set');

  const url = new URL(json.location as string);
  const state = url.searchParams.get('state') as string;
  const pending = await store.consume(state);
  assert.ok(pending);

  const value = /^__Host-css-oidc-login-pending=([^;]+)/u.exec(cookie as string)?.[1];
  assert.equal(value, pending.handle);
  assert.notEqual(value, state);
  assert.equal((json.location as string).includes(pending.handle), false);
});

// SameSite=Strict is what makes the cross-site form submission fail: the
// victim's browser holds a cookie but does not send it. Lax would. The
// `__Host-` prefix is what stops a sibling host from writing the cookie in the
// first place, and a browser only honours it for a Secure cookie at Path=/
// with no Domain — so the three attributes are one property, not three.
test('locks the cookie to this host and keeps it off cross-site requests', async () => {
  const store = new PendingLoginStore(300000);
  const handler = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'https://pod.example/.account/login/oidc/callback/',
  });

  const { metadata } = await handler.handle(input);
  const cookie = String(metadata?.get(namedNode(setCookiePredicate))?.value);

  assert.match(cookie, /^__Host-/u);
  assert.match(cookie, /; Secure;/u);
  assert.match(cookie, /; Path=\/;/u);
  assert.equal(/; ?Domain=/iu.test(cookie), false, 'a __Host- cookie may not name a domain');
  assert.match(cookie, /; SameSite=Strict$/u);
  assert.match(cookie, /; HttpOnly;/u);
  assert.match(cookie, /; Max-Age=300;/u);
});

// The name the browser is given and the name a deployment maps in the cookie
// parser are the same field, so a configured name carries the prefix too.
test('lets a deployment name the cookie, under the same prefix', async () => {
  const store = new PendingLoginStore(600000, 'pod-pending-login');
  const handler = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'https://pod.example/cb',
  });

  const { metadata } = await handler.handle(input);
  assert.match(String(metadata?.get(namedNode(setCookiePredicate))?.value), /^__Host-pod-pending-login=/u);
  assert.equal(store.cookieName, '__Host-pod-pending-login');
});

// A browser stores no __Host- cookie over plain HTTP, so every login would end
// at the callback with a cookie that was never set. Saying so where the login
// starts is the difference between a misconfigured deployment and a package
// that looks broken.
test('refuses to start a login when the callback is not HTTPS', async () => {
  const handler = new OidcRedirectHandler({
    store: new PendingLoginStore(),
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'http://localhost:3000/.account/login/oidc/callback/',
  });

  await assert.rejects(
    handler.handle(input),
    (error: unknown): boolean =>
      (error as { statusCode?: number }).statusCode === 500 &&
      /only stored by a browser over HTTPS/u.test(String(error)) &&
      /http:\/\/localhost:3000/u.test(String(error)),
  );
});

// A store with no room refuses rather than making room, so the browser that
// started a login and is away at the provider keeps it. What the person who
// asked for the login that could not be taken sees is this: a server that is
// momentarily out of room, not a request of theirs that was wrong.
test('turns a login away when the store has no room left for it', async () => {
  const store = new PendingLoginStore(600000, 'pending', 1);
  const handler = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'https://pod.example/.account/login/oidc/callback/',
  });

  const first = new URL((await handler.handle(input)).json.location as string);

  await assert.rejects(
    handler.handle(input),
    (error: unknown): boolean => (error as { statusCode?: number }).statusCode === 503,
  );
  assert.ok(
    await store.peek(first.searchParams.get('state') as string),
    'the login that was already in progress was taken away',
  );
});

// The HTML view only answers a GET that prefers HTML over JSON, so a GET
// carrying `Accept: */*` — curl, a crawler, a cross-site `<img src>` — falls
// through to this handler. Starting a login for it would write a pending entry
// and hand out a cookie that replaces the one a login already in flight in
// that browser needs, which costs its owner their login. GET is the method
// that gets here by accident, but it is not the claim: the claim is that POST
// is the only method that starts a login, so a method that is neither is
// refused too.
test('starts a login on a POST and on nothing else', async () => {
  const store = new PendingLoginStore();
  const created: string[] = [];
  store.create = async (state: string): Promise<void> => {
    created.push(state);
  };
  const handler = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'https://pod.example/.account/login/oidc/callback/',
  });

  const isMethodNotAllowed = (error: unknown): boolean =>
    (error as { statusCode?: number }).statusCode === 405;

  for (const method of ['GET', 'HEAD', 'PUT', 'DELETE', 'PATCH']) {
    const other = { method, target, json: {}, metadata: {}} as never;
    // Both halves: what a waterfall consults before it picks a handler, and
    // the one a wrapper that has already made its own choice calls directly.
    await assert.rejects(handler.handleSafe(other), isMethodNotAllowed, `${method} was not refused`);
    await assert.rejects(handler.handle(other), isMethodNotAllowed, `${method} was not refused`);
    assert.deepEqual(created, [], `a ${method} started a login`);
  }

  await handler.handle(input);
  assert.equal(created.length, 1, 'a POST did not start a login');
});

// `location` is read by the start template as `location.href = body.location`,
// so whatever reaches it is navigated to. A discovery document naming
// `javascript:...` as its authorization endpoint would put script on this
// server's own origin there; it has to be stopped before a login is even
// started, and the refusal is the provider's failure, not the caller's.
test('never hands the browser an authorization endpoint that is not https', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({
    issuer: 'https://idp.example',
    authorization_endpoint: 'javascript:alert(document.domain)//',
    token_endpoint: 'https://idp.example/token',
  }), { status: 200 })) as unknown as typeof fetch;

  try {
    const store = new PendingLoginStore();
    const handler = new OidcRedirectHandler({
      store,
      discovery: new OidcDiscovery('https://idp.example'),
      clientId: 'pod-client',
      callbackUrl: 'https://pod.example/.account/login/oidc/callback/',
    });

    let result: { json: { location?: unknown }} | undefined;
    await assert.rejects(
      (async (): Promise<void> => {
        result = await handler.handle(input) as never;
      })(),
      (error: unknown): boolean => {
        assert.equal((error as { statusCode?: number }).statusCode, 502);
        assert.match(String(error), /authorization_endpoint that is not an absolute HTTPS URL/u);
        return true;
      },
    );
    assert.equal(result, undefined, 'a javascript: endpoint reached the browser as json.location');
  } finally {
    globalThis.fetch = original;
  }
});
