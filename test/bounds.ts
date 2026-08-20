import assert from 'node:assert/strict';

/**
 * The longest a request this package makes may wait before it gives up. It is
 * stated here rather than read from the implementation on purpose: a test that
 * waits for a deadline has to give up somewhere, and that somewhere is the
 * assertion. A deadline set beyond this fails the test that waits for it.
 */
export const DEADLINE_BOUND_MS = 10000;

/**
 * Backstop for a test that waits a deadline out. What should fail such a test
 * is the assertion in {@link neverAnswers}, which says what went wrong; this
 * only stops a run that hangs some other way, so it has to be the later of the
 * two. It is also how long {@link endlessBody} goes on for: longer than any
 * test here is willing to wait, and finite so that a run which has already
 * given up still ends.
 */
export const BEYOND_PATIENCE_MS = DEADLINE_BOUND_MS * 2;

/**
 * Answers the way a host that has stopped answering does: not at all. What
 * ends the wait is the request's own deadline, so a request made without one —
 * or with one set far out — fails here rather than passing.
 */
export const neverAnswers = async (init?: { signal?: AbortSignal }): Promise<never> => {
  const { signal } = init ?? {};
  assert.ok(signal instanceof AbortSignal, 'the request carries no abort signal');

  // The timer behind AbortSignal.timeout deliberately does not hold the event
  // loop open, so this one does, and it is also what bounds the wait.
  let patience: ReturnType<typeof setTimeout>;
  const stillWaiting = await new Promise<boolean>((resolve): void => {
    patience = setTimeout((): void => resolve(true), DEADLINE_BOUND_MS);
    signal.addEventListener('abort', (): void => resolve(false), { once: true });
  });
  clearTimeout(patience!);

  assert.equal(stillWaiting, false, `the request was still waiting after ${DEADLINE_BOUND_MS}ms`);
  throw signal.reason;
};

/**
 * A body that goes on for longer than any test here is willing to wait, the
 * way a host that keeps feeding a reader for as long as it keeps reading does.
 * An implementation that buffers the whole body and only then looks at its
 * size never gets past this.
 */
export const endlessBody = (contentType: string): Response => {
  const chunk = new TextEncoder().encode('#'.repeat(4096));
  const until = Date.now() + BEYOND_PATIENCE_MS;
  const body = new ReadableStream({
    async pull(controller): Promise<void> {
      if (Date.now() > until) {
        controller.close();
        return;
      }
      // Paced, so that an implementation without a cap runs out of the test's
      // time rather than out of the machine's memory.
      await new Promise((resolve): void => {
        setTimeout(resolve, 1);
      });
      controller.enqueue(chunk);
    },
  });
  return new Response(body, { status: 200, headers: { 'content-type': contentType }});
};
