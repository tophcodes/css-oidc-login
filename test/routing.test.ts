import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AbsolutePathInteractionRoute, InteractionRouteHandler, LocationInteractionHandler,
  RelativePathInteractionRoute, WaterfallHandler,
} from '@solid/community-server';
import type { JsonInteractionHandler } from '@solid/community-server';
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
 */
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
    callbackUrl: 'https://pod.example/.account/login/oidc/callback/',
  });
  // A second route, so the waterfall has a sibling to disagree with, the way a
  // deployment that wires both routes does. Its handler is never reached: what
  // it contributes is the 404 of a route that was not asked for.
  const callback = { canHandle: async (): Promise<void> => undefined, handle: async (): Promise<never> => {
    throw new Error('the callback route answered a request for the start route');
  }} as unknown as JsonInteractionHandler;

  return new LocationInteractionHandler(new WaterfallHandler([
    new InteractionRouteHandler(startRoute, start),
    new InteractionRouteHandler(callbackRoute, callback),
  ]));
};

const request = (method: string): never => ({
  method,
  target: { path: 'https://pod.example/.account/login/oidc/' },
  json: {},
  metadata: {},
} as never);

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

// A request for a route nobody claims is still a 404, so the status above is
// not the waterfall having lost the ability to tell routes apart.
test('still answers an unclaimed route with a not-found', async () => {
  const handler = chain(new PendingLoginStore());
  const elsewhere = {
    method: 'POST',
    target: { path: 'https://pod.example/.account/login/password/' },
    json: {},
    metadata: {},
  } as never;

  await assert.rejects(handler.handleSafe(elsewhere), (error: unknown): boolean => statusOf(error) === 404);
});
