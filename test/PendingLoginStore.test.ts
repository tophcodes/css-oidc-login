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
// more than its cap, and it is the ones that arrive past the cap that are
// turned away rather than the ones already in it.
test('holds no more logins than its cap, however many are started', async () => {
  const cap = 10;
  const started = 100;
  const store = new PendingLoginStore(600000, 'pending', cap);
  let refused = 0;

  for (let i = 0; i < started; i++) {
    try {
      await store.create(`state-${i}`, { codeVerifier: 'v', handle: 'h' });
    } catch {
      refused += 1;
    }
  }

  const held: number[] = [];
  for (let i = 0; i < started; i++) {
    if (await store.peek(`state-${i}`)) {
      held.push(i);
    }
  }

  assert.equal(held.length, cap, `the store holds ${held.length} logins in progress, not ${cap}`);
  assert.deepEqual(held, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(refused, started - cap);
});

// The caller of a full store did nothing wrong and the condition passes on its
// own, so it is answered as a server that is momentarily out of room rather
// than as a bad request or a fault.
test('refuses a login it has no room for as a temporary condition of this server', async () => {
  const store = new PendingLoginStore(600000, 'pending', 1);
  await store.create('the-one-it-holds', { codeVerifier: 'v', handle: 'h' });

  await assert.rejects(
    store.create('one-too-many', { codeVerifier: 'v', handle: 'h' }),
    (error: unknown): boolean => (error as { statusCode?: number }).statusCode === 503,
  );
});

// The bound is only worth having if it cannot be turned around: filling the
// store is unauthenticated and costs nothing, so a store that made room by
// dropping an entry would hand a flooder the power to end anyone's login while
// they are still at the provider. Every entry the flood writes is live, so
// expiry reclaims none of them and it is the eviction rule alone that decides
// who loses. Whatever it drops here, it may not be the victim.
test('does not let a flood take away a login that is already in progress', async () => {
  const cap = 1000;
  const store = new PendingLoginStore(600000, 'pending', cap);

  // The victim is inside their TTL and away at the provider, holding the
  // handle their browser was given.
  await store.create('victim', { codeVerifier: 'victim-verifier', handle: 'victim-handle' });

  // Ten times the store's worth of unauthenticated starts, none of them ever
  // returning from a provider.
  let refused = 0;
  for (let i = 0; i < cap * 10; i++) {
    try {
      await store.create(`flood-${i}`, { codeVerifier: 'v', handle: 'h' });
    } catch {
      refused += 1;
    }
  }

  assert.deepEqual(
    await store.consume('victim'),
    { codeVerifier: 'victim-verifier', handle: 'victim-handle' },
    'the flood took away a login that was in progress',
  );
  assert.ok(refused > 0, 'the flood was never turned away, so the store is not bounded');
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
