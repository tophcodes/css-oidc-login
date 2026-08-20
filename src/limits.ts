/**
 * Every request this package makes leaves the server waiting on a host it does
 * not control: the provider's discovery document, its token endpoint, and the
 * profile a WebID resolves to. All three are bounded the same way, so that one
 * unresponsive or endless host cannot occupy a worker or its memory. The
 * limits are orders of magnitude above what any of these answers legitimately
 * needs and still finite.
 */
export const RESPONSE_TIMEOUT_MS = 5000;
export const RESPONSE_MAX_BYTES = 1048576;

/**
 * Reads a body while counting bytes, so a response that never ends or that
 * lies about its length still costs a bounded amount of memory. `tooLarge`
 * supplies the error for that case, since what a caller has to raise differs;
 * anything the stream itself raises is passed through untouched.
 */
export const readCapped = async (response: Response, tooLarge: () => Error): Promise<string> => {
  if (!response.body) {
    return '';
  }

  const decoder = new TextDecoder();
  let read = 0;
  let text = '';
  for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
    read += chunk.byteLength;
    if (read > RESPONSE_MAX_BYTES) {
      throw tooLarge();
    }
    text += decoder.decode(chunk, { stream: true });
  }
  return text + decoder.decode();
};
