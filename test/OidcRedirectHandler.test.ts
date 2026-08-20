import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DataFactory } from 'n3';
import { OidcRedirectHandler } from '../src/OidcRedirectHandler.ts';
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

  const value = /^css-oidc-login-pending=([^;]+)/u.exec(cookie as string)?.[1];
  assert.equal(value, pending.handle);
  assert.notEqual(value, state);
  assert.equal((json.location as string).includes(pending.handle), false);
});

// SameSite=Strict is what makes the cross-site form submission fail: the
// victim's browser holds a cookie but does not send it. Lax would.
test('scopes the cookie to the callback and keeps it off cross-site requests', async () => {
  const store = new PendingLoginStore(300000);
  const handler = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'https://pod.example/.account/login/oidc/callback/',
  });

  const { metadata } = await handler.handle(input);
  const cookie = String(metadata?.get(namedNode(setCookiePredicate))?.value);

  assert.match(cookie, /; SameSite=Strict$/u);
  assert.match(cookie, /; HttpOnly;/u);
  assert.match(cookie, /; Path=\/\.account\/login\/oidc\/callback\/;/u);
  assert.match(cookie, /; Max-Age=300;/u);
});

test('lets a deployment name the cookie', async () => {
  const store = new PendingLoginStore(600000, 'pod-pending-login');
  const handler = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: 'https://pod.example/cb',
  });

  const { metadata } = await handler.handle(input);
  assert.match(String(metadata?.get(namedNode(setCookiePredicate))?.value), /^pod-pending-login=/u);
});
