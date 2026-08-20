import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DataFactory } from 'n3';
import {
  AbsolutePathInteractionRoute, InteractionRouteHandler, LocationInteractionHandler,
  RelativePathInteractionRoute, RepresentationMetadata, WaterfallHandler,
} from '@solid/community-server';
import type { JsonInteractionHandler } from '@solid/community-server';
import { OidcCallbackHandler } from '../src/OidcCallbackHandler.ts';
import { OidcRedirectHandler } from '../src/OidcRedirectHandler.ts';
import { PendingLoginStore } from '../src/PendingLoginStore.ts';

/**
 * What a client is told is decided by the chain a deployment wires the
 * handlers into, not by the handler alone. That chain is a waterfall over one
 * route handler per route: a route that is not the requested one refuses with
 * 404, and the refusals of every route are combined into the one error the
 * client sees. A set of 4xx that do not agree on a status collapses to a plain
 * 400 with everything the individual errors carried — the method among it —
 * dropped, which is why the status is asserted here rather than only on the
 * handler.
 *
 * Both routes are wired, and both handlers are the real ones: each is the
 * other's sibling in the waterfall, and the callback's answer travels one
 * further step than the start route's, through the login resolution its
 * handler inherits. That step is where a status of its own has been lost
 * before.
 */
const { namedNode } = DataFactory;

const START = 'https://pod.example/.account/login/oidc/';
const CALLBACK = 'https://pod.example/.account/login/oidc/callback/';
const WEBID = 'https://pod.example/alice/profile/card#me';
const HANDLE = 'handle-of-the-browser-that-started-the-login';

/** Predicates are read off a store instance, the way the handlers read them. */
const { cookiePredicate } = new PendingLoginStore();

const chain = (store: PendingLoginStore): JsonInteractionHandler => {
  const base = new AbsolutePathInteractionRoute('https://pod.example/.account/login/');
  const startRoute = new RelativePathInteractionRoute(base, 'oidc/');
  const callbackRoute = new RelativePathInteractionRoute(startRoute, 'callback/');
  const discovery = {
    endpoints: async () => ({
      authorization: 'https://idp.example/authorize',
      token: 'https://idp.example/token',
    }),
  };

  const start = new OidcRedirectHandler({
    store,
    discovery: discovery as never,
    clientId: 'pod-client',
    callbackUrl: CALLBACK,
  });

  const callback = new OidcCallbackHandler({
    accountStore: {
      updateSetting: async (): Promise<void> => undefined,
      getSetting: async (): Promise<undefined> => undefined,
    } as never,
    cookieStore: {
      generate: async (): Promise<string> => 'account-cookie',
      delete: async (): Promise<void> => undefined,
    } as never,
    store,
    storage: { find: async (): Promise<unknown[]> => [{ id: 'l1', webId: WEBID, accountId: 'acc-1' }]} as never,
    discovery: discovery as never,
    issuer: 'https://idp.example',
    clientId: 'pod-client',
    clientSecret: 'shh',
    callbackUrl: CALLBACK,
  });
  // Neither the provider nor the profile decides what this file is about: the
  // method is refused before either is reached, and both have tests of their own.
  (callback as unknown as { exchange: unknown }).exchange = async (): Promise<unknown> =>
    ({ webid: WEBID, sub: 'subject-alice' });
  (callback as unknown as { assertProfileGrantsLogin: unknown }).assertProfileGrantsLogin =
    async (): Promise<undefined> => undefined;

  return new LocationInteractionHandler(new WaterfallHandler([
    new InteractionRouteHandler(startRoute, start),
    new InteractionRouteHandler(callbackRoute, callback),
  ]));
};

const request = (method: string, path = START, json: unknown = {}, handle?: string): never => {
  const target = { path };
  const metadata = new RepresentationMetadata(target);
  if (handle) {
    metadata.add(namedNode(cookiePredicate), handle);
  }
  return { method, target, json, metadata } as never;
};

const statusOf = (error: unknown): number | undefined => (error as { statusCode?: number }).statusCode;

test('tells a client that reaches the start route with the wrong method which methods it may use', async () => {
  const handler = chain(new PendingLoginStore());

  await assert.rejects(
    handler.handleSafe(request('GET')),
    (error: unknown): boolean =>
      statusOf(error) === 405 && /Only POST requests are supported/u.test(String(error)),
  );
});

// The route still has to be the one that answers a POST, or the status above
// is bought by a handler that no longer does its job.
test('answers a POST to the start route through the same chain', async () => {
  const store = new PendingLoginStore();
  const { json } = await chain(store).handleSafe(request('POST'));

  const url = new URL(json.location as string);
  assert.equal(url.origin + url.pathname, 'https://idp.example/authorize');
  assert.ok(await store.peek(url.searchParams.get('state') as string));
});

// The same for the callback, whose refusal has one more step to survive: the
// login resolution its handler inherits sits between it and the waterfall, and
// a status that does not reach the client is a status nobody has.
test('tells a client that reaches the callback route with the wrong method which methods it may use', async () => {
  const store = new PendingLoginStore();
  await store.create('s-routing', { codeVerifier: 'v', handle: HANDLE });
  const handler = chain(store);

  for (const method of [ 'GET', 'HEAD', 'PUT', 'DELETE', 'PATCH' ]) {
    await assert.rejects(
      handler.handleSafe(request(method, CALLBACK, { state: 's-routing', code: 'c' }, HANDLE)),
      (error: unknown): boolean =>
        statusOf(error) === 405 && /Only POST requests are supported/u.test(String(error)),
      `${method} to the callback route was not refused as a method`,
    );
    // And the login it named is still there for the browser that started it.
    assert.ok(await store.peek('s-routing'), `a ${method} spent the login`);
  }
});

test('answers a POST to the callback route through the same chain', async () => {
  const store = new PendingLoginStore();
  await store.create('s-routing-post', { codeVerifier: 'v', handle: HANDLE });

  const { json } = await chain(store)
    .handleSafe(request('POST', CALLBACK, { state: 's-routing-post', code: 'c' }, HANDLE));

  assert.equal(json.authorization, 'account-cookie');
  assert.equal(await store.peek('s-routing-post'), undefined);
});

// A request for a route nobody claims is still a 404, so the status above is
// not the waterfall having lost the ability to tell routes apart.
test('still answers an unclaimed route with a not-found', async () => {
  const handler = chain(new PendingLoginStore());

  await assert.rejects(
    handler.handleSafe(request('POST', 'https://pod.example/.account/login/password/')),
    (error: unknown): boolean => statusOf(error) === 404,
  );
});
