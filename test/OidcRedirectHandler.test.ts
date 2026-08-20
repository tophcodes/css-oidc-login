import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OidcRedirectHandler } from '../src/OidcRedirectHandler.ts';
import { PendingLoginStore } from '../src/PendingLoginStore.ts';

const discovery = {
  endpoints: async () => ({
    authorization: 'https://idp.example/authorize',
    token: 'https://idp.example/token',
  }),
};

test('builds an authorization URL with PKCE and the configured scopes', async () => {
  const store = new PendingLoginStore();
  const handler = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'https://pod.example/.account/login/oidc/callback/',
    scopes: 'openid profile',
  });

  const { json } = await handler.handle();
  const url = new URL(json.location as string);

  assert.equal(url.origin + url.pathname, 'https://idp.example/authorize');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('client_id'), 'pod-client');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://pod.example/.account/login/oidc/callback/');
  assert.equal(url.searchParams.get('scope'), 'openid profile');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('code_challenge'));

  // The state must be redeemable exactly once.
  const state = url.searchParams.get('state') as string;
  assert.ok(await store.consume(state));
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

  const first = new URL((await handler.handle()).json.location as string);
  const second = new URL((await handler.handle()).json.location as string);

  assert.notEqual(first.searchParams.get('state'), second.searchParams.get('state'));
  assert.notEqual(first.searchParams.get('code_challenge'), second.searchParams.get('code_challenge'));
});
