import { MethodNotAllowedHttpError } from '@solid/community-server';

/**
 * Both routes of this package act: one starts a login and hands the browser a
 * cookie, the other spends it. Neither has a safe reading, so both answer only
 * to POST.
 *
 * The server's own `ViewInteractionHandler` would impose the same thing, but
 * only for a deployment that wraps the handler in it, and a deployment that
 * forgets sees a working login rather than a missing guard. So the handlers
 * refuse the method themselves.
 *
 * They refuse it where the work is done rather than in `canHandle`. A route
 * that refuses in `canHandle` is a route the surrounding waterfall keeps
 * looking past: it collects that refusal alongside the "not my route" of every
 * sibling and combines them, and a set of 4xx that do not agree on a status
 * becomes a plain 400 with the method dropped. Claiming the route and refusing
 * the method inside it is what puts this status in front of the client, which
 * is the only place it is of any use.
 */
export const assertPostOnly = (method: string): void => {
  if (method !== 'POST') {
    throw new MethodNotAllowedHttpError([method], 'Only POST requests are supported.');
  }
};
