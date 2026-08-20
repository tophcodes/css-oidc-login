import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PendingLoginStore } from '../src/PendingLoginStore.ts';

test('returns the stored login once and then forgets it', async () => {
  const store = new PendingLoginStore();
  await store.create('state-1', { codeVerifier: 'v1', handle: 'h1' });

  assert.deepEqual(await store.consume('state-1'), { codeVerifier: 'v1', handle: 'h1' });
  assert.equal(await store.consume('state-1'), undefined);
});

test('returns undefined for an unknown state', async () => {
  const store = new PendingLoginStore();
  assert.equal(await store.consume('nope'), undefined);
});

test('returns undefined once the entry has expired', async () => {
  const store = new PendingLoginStore(-1);
  await store.create('state-2', { codeVerifier: 'v2', handle: 'h2' });
  assert.equal(await store.consume('state-2'), undefined);
});

// The handle is checked before the login is spent, so the store has to be able
// to hand it over without spending it.
test('hands over the stored login without spending it', async () => {
  const store = new PendingLoginStore();
  await store.create('state-peek', { codeVerifier: 'v3', handle: 'h3' });

  assert.deepEqual(await store.peek('state-peek'), { codeVerifier: 'v3', handle: 'h3' });
  assert.deepEqual(await store.peek('state-peek'), { codeVerifier: 'v3', handle: 'h3' });
  assert.deepEqual(await store.consume('state-peek'), { codeVerifier: 'v3', handle: 'h3' });
  assert.equal(await store.peek('state-peek'), undefined);
});

test('does not hand over an expired login', async () => {
  const store = new PendingLoginStore(-1);
  await store.create('state-peek-expired', { codeVerifier: 'v4', handle: 'h4' });
  assert.equal(await store.peek('state-peek-expired'), undefined);
});

test('carries the __Host- prefix whether or not the configured name does', async () => {
  assert.equal(new PendingLoginStore().cookieName, '__Host-css-oidc-login-pending');
  assert.equal(new PendingLoginStore(600000, 'named').cookieName, '__Host-named');
  assert.equal(new PendingLoginStore(600000, '__Host-named').cookieName, '__Host-named');
});

test('refuses to serialise a cookie for a callback that is not HTTPS', async () => {
  const store = new PendingLoginStore();
  assert.throws(
    () => store.cookie('h', 'http://pod.example/cb'),
    /only stored by a browser over HTTPS/u,
  );
  assert.throws(
    () => store.expiredCookie('http://pod.example/cb'),
    /only stored by a browser over HTTPS/u,
  );
});
