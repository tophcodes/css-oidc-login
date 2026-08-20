import { MethodNotAllowedHttpError } from '@solid/community-server';

/**
 * Both routes of this package act: one starts a login and hands the browser a
 * cookie, the other spends it. Neither has a safe reading, so both answer only
 * to POST.
 *
 * The server's own `ViewInteractionHandler` would impose the same thing, but
 * only for a deployment that wraps the handler in it, and a deployment that
 * forgets sees a working login rather than a missing guard. So the handlers
 * refuse the method themselves, in `canHandle` and again where the work is
 * done, since a composition may reach the second without the first.
 */
export const assertPostOnly = (method: string): void => {
  if (method !== 'POST') {
    throw new MethodNotAllowedHttpError([method], 'Only POST requests are supported.');
  }
};
