import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout } from 'node:timers/promises';
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

// The route that fills this map is unauthenticated and an abandoned entry is
// never asked for again, so nothing else ever takes one out. What is asserted
// here is the bound itself: however many logins are started, the map holds no
// more than its cap, and what it holds is the most recent ones rather than
// whatever it happened to accept first.
test('holds no more logins than its cap, however many are started', async () => {
  const cap = 10;
  const started = 100;
  const store = new PendingLoginStore(600000, 'pending', cap);

  for (let i = 0; i < started; i++) {
    await store.create(`state-${i}`, { codeVerifier: 'v', handle: 'h' });
  }

  const held: number[] = [];
  for (let i = 0; i < started; i++) {
    if (await store.peek(`state-${i}`)) {
      held.push(i);
    }
  }

  assert.equal(held.length, cap, `the store holds ${held.length} logins in progress, not ${cap}`);
  assert.deepEqual(held, [90, 91, 92, 93, 94, 95, 96, 97, 98, 99]);
});

// Expiry is what reclaims, and the cap is only the backstop: a store whose
// entries have all expired takes new logins without dropping any of them.
test('makes room out of expired logins rather than out of the cap', async () => {
  const store = new PendingLoginStore(100, 'pending', 4);
  for (let i = 0; i < 4; i++) {
    await store.create(`abandoned-${i}`, { codeVerifier: 'v', handle: 'h' });
  }
  await setTimeout(150);

  for (let i = 0; i < 4; i++) {
    await store.create(`live-${i}`, { codeVerifier: 'v', handle: 'h' });
  }

  for (let i = 0; i < 4; i++) {
    assert.ok(await store.peek(`live-${i}`), `live-${i} was evicted`);
  }
});
