/**
 * Newline-delimited JSON-RPC framing, as MCP's stdio transport defines it.
 *
 * The only subtlety is that a stream boundary falls wherever the OS decides,
 * not on message boundaries: a single `data` event can carry half a message,
 * three messages, or three and a half. Buffering until a newline is the whole
 * job, and getting it wrong shows up as rare, unreproducible corruption under
 * load — so it lives here, alone, with tests.
 */

export class LineFramer {
  constructor() {
    /** @type {string} */
    this._buf = '';
  }

  /**
   * Feed a chunk; get back whatever complete messages it completed.
   *
   * Malformed lines are returned as `{ raw, error }` rather than thrown. A
   * proxy that dies on one bad line takes the agent down with it, and the
   * upstream server is not ours to trust.
   *
   * @param {string|Buffer} chunk
   * @returns {{ message?: unknown, raw: string, error?: Error }[]}
   */
  push(chunk) {
    this._buf += chunk.toString();
    const out = [];
    let nl;
    while ((nl = this._buf.indexOf('\n')) !== -1) {
      const raw = this._buf.slice(0, nl).replace(/\r$/, '');
      this._buf = this._buf.slice(nl + 1);
      if (raw.trim() === '') continue;
      try {
        out.push({ message: JSON.parse(raw), raw });
      } catch (err) {
        out.push({ raw, error: /** @type {Error} */ (err) });
      }
    }
    return out;
  }

  /** @returns {string} Any trailing partial line, for diagnostics on exit. */
  get pending() {
    return this._buf;
  }
}

/**
 * @param {unknown} msg
 * @returns {string}
 */
export function encode(msg) {
  return JSON.stringify(msg) + '\n';
}

/**
 * A request is a message with both a method and an id. Notifications have a
 * method and no id; responses have an id and no method.
 *
 * @param {any} msg
 * @returns {boolean}
 */
export function isRequest(msg) {
  return Boolean(msg) && typeof msg === 'object' && 'method' in msg && 'id' in msg && msg.id !== null;
}

/**
 * @param {any} msg
 * @returns {boolean}
 */
export function isResponse(msg) {
  return (
    Boolean(msg) &&
    typeof msg === 'object' &&
    !('method' in msg) &&
    'id' in msg &&
    ('result' in msg || 'error' in msg)
  );
}

/**
 * Build the MCP-shaped "the tool did not run" reply.
 *
 * This is deliberately a successful JSON-RPC response carrying `isError`,
 * not a JSON-RPC error. The distinction matters: a protocol-level error is
 * invisible to the model, while this reaches it as tool output, so the agent
 * learns it was refused and why, and can choose a different course instead of
 * retrying the same blocked call in a loop.
 *
 * @param {string|number} id
 * @param {string} text
 * @returns {object}
 */
export function toolRefusal(id, text) {
  return {
    jsonrpc: '2.0',
    id,
    result: {
      content: [{ type: 'text', text }],
      isError: true,
    },
  };
}
