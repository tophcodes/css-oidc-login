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
