import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout } from 'node:timers/promises';
import { DataFactory } from 'n3';
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

// What a refusal says is said to whoever asked, and nothing authenticates the
// asking. The cap is the size of the store: a caller told the number knows what
// a flood costs and can tell from a single refusal how close the store already
// is, which is the measurement a flood needs and the wait costs them nothing.
test('does not tell the caller how much room the store has', async () => {
  const cap = 3;
  const store = new PendingLoginStore(600000, 'pending', cap);
  for (let i = 0; i < cap; i++) {
    await store.create(`held-${i}`, { codeVerifier: 'v', handle: 'h' });
  }

  await assert.rejects(
    store.create('one-too-many', { codeVerifier: 'v', handle: 'h' }),
    (error: unknown): boolean => !new RegExp(`\\b${cap}\\b`, 'u').test(String(error)),
  );
});

// The condition passes on its own, and every entry is gone within one TTL of
// being written even if nobody completes a login. So the refusal can say how
// long the wait is at the outside, which is what turns "try again later" into
// something a client can act on without guessing.
test('says how long the wait for room is at the outside', async () => {
  const store = new PendingLoginStore(600000, 'pending', 1);
  await store.create('the-one-it-holds', { codeVerifier: 'v', handle: 'h' });

  await assert.rejects(
    store.create('one-too-many', { codeVerifier: 'v', handle: 'h' }),
    (error: unknown): boolean => {
      const retryAfter = (error as { metadata?: { get: (term: unknown) => { value: string } | undefined }})
        .metadata?.get(DataFactory.namedNode(store.retryAfterPredicate));
      return retryAfter?.value === '600';
    },
  );
});

// Reclaiming walks the store from the front and stops at the first entry that
// is still live, which reclaims everything expired only while the order entries
// sit in is the order they expire in. Writing a state that is already there
// gives it a later expiry, so it has to move to the back as well — otherwise a
// live entry sits in front of expired ones and the room they hold is never
// given back, and the store starts refusing logins it has room for.
test('keeps the store reclaimable when a state is written again', async () => {
  const ttl = 1000;
  const store = new PendingLoginStore(ttl, 'pending', 2);

  await store.create('first', { codeVerifier: 'v1', handle: 'h1' });
  await setTimeout(600);
  await store.create('second', { codeVerifier: 'v2', handle: 'h2' });
  await setTimeout(200);
  // The same login again, the way a browser that starts one twice would: it
  // now expires after `second` does, whatever order it was written in.
  await store.create('first', { codeVerifier: 'v1', handle: 'h1' });

  // A moment at which `second` has expired and the rewritten `first` has not.
  await setTimeout(900);

  await store.create('third', { codeVerifier: 'v3', handle: 'h3' });
  assert.ok(await store.peek('third'), 'the expired login never gave its room back');
  assert.ok(await store.peek('first'), 'the login that was written again was dropped instead');
  assert.equal(await store.peek('second'), undefined);
});

// The cap turns away what is new to the store, not a login already in it: a
// state written again is one that already holds its room, and a store with
// none left has none to give it either way. Refused there, a browser that
// starts the same login twice would lose the one it had, and the entry is
// taken out to be rewritten by the time the refusal would happen.
test('renews a login it already holds even when there is no room left', async () => {
  const store = new PendingLoginStore(600000, 'pending', 2);
  await store.create('held-1', { codeVerifier: 'v1', handle: 'h1' });
  await store.create('held-2', { codeVerifier: 'v2', handle: 'h2' });

  await store.create('held-1', { codeVerifier: 'v1-again', handle: 'h1-again' });

  assert.deepEqual(
    await store.peek('held-1'),
    { codeVerifier: 'v1-again', handle: 'h1-again' },
    'the login that was written again was refused by the cap it already fits under',
  );
  assert.ok(await store.peek('held-2'), 'the other login in progress was dropped');
});
