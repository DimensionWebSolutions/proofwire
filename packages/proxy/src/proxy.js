import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { LineFramer, encode, isRequest, isResponse, toolRefusal } from './jsonrpc.js';
import { History, redact, entryHash } from '@proofwire/core';

/**
 * A transparent MCP proxy that enforces policy and writes receipts.
 *
 * It sits between an agent and an MCP server, speaking the same protocol to
 * both, so adopting it is a change to one line of configuration:
 *
 *     "command": "npx", "args": ["-y", "@acme/mcp-crm"]
 *     "command": "pw",  "args": ["proxy", "--", "npx", "-y", "@acme/mcp-crm"]
 *
 * Everything that is not a `tools/call` is forwarded untouched. That matters
 * more than it sounds: MCP gains methods faster than any proxy can track, and
 * a proxy that only forwards what it recognises breaks on the next release.
 */

const RUNTIME = 'proofwire-proxy/0.1.0';

/**
 * Pull a dotted path out of an object.
 *
 * @param {unknown} obj
 * @param {string} dotted
 * @returns {unknown}
 */
function pluck(obj, dotted) {
  let cur = obj;
  for (const part of dotted.split('.')) {
    if (cur === null || cur === undefined) return undefined;
    cur = /** @type {Record<string, unknown>} */ (cur)[part];
  }
  return cur;
}

/**
 * Extract the clear-text numbers budgets aggregate over.
 *
 * Configured per tool pattern, because only the operator knows that their
 * payments tool reports cents and their invoicing tool reports dollars:
 *
 *     "metrics": {
 *       "stripe.*": { "amount_usd": { "from": "params.amount", "scale": 0.01 } }
 *     }
 *
 * @param {Record<string, any>} config
 * @param {string} target
 * @param {unknown} params
 * @returns {Record<string, number>}
 */
export function extractMetrics(config, target, params) {
  /** @type {Record<string, number>} */
  const out = {};
  for (const [pattern, spec] of Object.entries(config ?? {})) {
    const rx = new RegExp(
      '^' + pattern.split('*').map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$',
    );
    if (!rx.test(target)) continue;
    for (const [name, rule] of Object.entries(/** @type {Record<string, any>} */ (spec))) {
      const from = typeof rule === 'string' ? rule : rule.from;
      const scale = typeof rule === 'string' ? 1 : (rule.scale ?? 1);
      const raw = Number(pluck({ params }, from));
      if (Number.isFinite(raw)) out[name] = raw * scale;
    }
  }
  return out;
}

/**
 * Quote an argument for cmd.exe, which is what `shell: true` invokes on
 * Windows. Node concatenates argv into one string in shell mode without
 * escaping anything, so unquoted spaces silently split into extra arguments.
 *
 * @param {string} s
 * @returns {string}
 */
function winQuote(s) {
  return /[\s"^&|<>()%!]/.test(s) ? '"' + s.replace(/"/g, '\\"') + '"' : s;
}

/**
 * Decide how to launch the upstream server.
 *
 * Windows makes this a genuine fork in the road. Since the fix for
 * CVE-2024-27980, Node refuses to spawn `.cmd` and `.bat` files without a
 * shell — and `npx`, `npm` and `yarn`, which is how nearly every MCP server is
 * launched, are exactly that. But turning the shell on unconditionally is
 * worse: in shell mode the command line is concatenated unescaped, so an
 * interpreter at `C:\Program Files\nodejs\node.exe` is split at the space and
 * nothing starts at all.
 *
 * So: a command that names a path or an executable is spawned directly; a bare
 * name, which might be a shim, goes through the shell with everything quoted.
 *
 * @param {string} command
 * @param {string[]} args
 * @returns {{ command: string, args: string[], shell: boolean }}
 */
export function launchSpec(command, args) {
  if (process.platform !== 'win32') return { command, args, shell: false };

  const namesAPath = /[\\/]/.test(command) || /\.(exe|com)$/i.test(command);
  if (namesAPath) return { command, args, shell: false };

  return { command: winQuote(command), args: args.map(winQuote), shell: true };
}

/**
 * @typedef {object} ProxyOptions
 * @property {import('@proofwire/core').ProofLog} log
 * @property {import('@proofwire/core').Policy} policy
 * @property {{ agent: string, session: string, principal: string }} actor
 * @property {(req: any) => Promise<{approved: boolean, by: string, note?: string}>} approver
 * @property {string} command
 * @property {string[]} args
 * @property {string} [namespace]  Prefix for tool names in receipts, e.g. `stripe`.
 * @property {Record<string, any>} [metrics]
 * @property {NodeJS.ReadableStream} [stdin]
 * @property {NodeJS.WritableStream} [stdout]
 * @property {NodeJS.WritableStream} [stderr]
 * @property {Record<string,string>} [env]
 */

export class McpProxy extends EventEmitter {
  /** @param {ProxyOptions} opts */
  constructor(opts) {
    super();
    this.opts = opts;
    this.log = opts.log;
    this.policy = opts.policy;
    this.namespace = opts.namespace ?? '';
    this.history = new History([...opts.log.entries]);

    /** In-flight upstream calls, keyed by JSON-RPC id. */
    this._pending = new Map();
    /** @type {import('node:child_process').ChildProcessWithoutNullStreams|null} */
    this.child = null;
    this.stats = { forwarded: 0, denied: 0, escalated: 0, approved: 0, errors: 0 };
  }

  /**
   * @param {string} name
   * @returns {string}
   */
  _qualify(name) {
    return this.namespace ? `${this.namespace}.${name}` : name;
  }

  /**
   * Start the upstream server and wire the two directions together.
   *
   * @returns {Promise<number>} The child's exit code.
   */
  start() {
    const stdin = this.opts.stdin ?? process.stdin;
    const stdout = this.opts.stdout ?? process.stdout;
    const stderr = this.opts.stderr ?? process.stderr;

    const spec = launchSpec(this.opts.command, this.opts.args);
    const child = spawn(spec.command, spec.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...(this.opts.env ?? {}) },
      shell: spec.shell,
    });
    this.child = child;

    const fromClient = new LineFramer();
    const fromServer = new LineFramer();

    stdin.on('data', (chunk) => {
      for (const { message, raw, error } of fromClient.push(chunk)) {
        if (error) {
          // Not ours to repair: hand it upstream and let the server object.
          child.stdin.write(raw + '\n');
          continue;
        }
        this._handleClientMessage(message, child, stdout).catch((err) => {
          this.stats.errors++;
          this.emit('error', err);
          if (isRequest(message)) {
            stdout.write(
              encode(toolRefusal(/** @type {any} */ (message).id, `Proofwire internal error: ${err.message}`)),
            );
          }
        });
      }
    });

    child.stdout.on('data', (chunk) => {
      for (const { message, raw, error } of fromServer.push(chunk)) {
        if (error) {
          stdout.write(raw + '\n');
          continue;
        }
        this._handleServerMessage(message, stdout);
      }
    });

    // The upstream server's logs are its own; pass them through untouched so
    // debugging the wrapped server still works.
    child.stderr.on('data', (chunk) => stderr.write(chunk));

    stdin.on('end', () => child.stdin.end());

    return new Promise((resolve) => {
      child.on('exit', (code) => {
        this.emit('exit', code ?? 0);
        resolve(code ?? 0);
      });
      child.on('error', (err) => {
        stderr.write(`proofwire: could not start "${this.opts.command}": ${err.message}\n`);
        this.emit('error', err);
        resolve(127);
      });
    });
  }

  /**
   * @param {any} message
   * @param {import('node:child_process').ChildProcessWithoutNullStreams} child
   * @param {NodeJS.WritableStream} stdout
   */
  async _handleClientMessage(message, child, stdout) {
    if (!isRequest(message) || message.method !== 'tools/call') {
      child.stdin.write(encode(message));
      return;
    }

    const target = this._qualify(message.params?.name ?? 'unknown');
    const params = message.params?.arguments ?? {};
    const actor = { ...this.opts.actor, runtime: RUNTIME };
    const metrics = extractMetrics(this.opts.metrics ?? {}, target, params);

    let decision = this.policy.decide(
      { kind: 'tool_call', target, params, metrics, actor },
      this.history,
    );

    /** @type {import('@proofwire/core').Decision['approval']} */
    let approval;

    if (decision.outcome === 'escalate') {
      this.stats.escalated++;
      // The approver sees a redacted preview, never the raw arguments. A
      // human clicking "approve" in Slack should not thereby paste a customer's
      // card number into Slack's message history.
      const { value: preview } = redact(params);
      const verdict = await this.opts.approver({
        target,
        params: preview,
        reason: decision.reason,
        rules: decision.rules,
        actor,
      });
      if (verdict.approved) {
        this.stats.approved++;
        approval = { by: verdict.by, at: new Date().toISOString(), note: verdict.note };
        decision = { ...decision, outcome: 'allow', reason: `${decision.reason} — approved by ${verdict.by}` };
      } else {
        decision = {
          ...decision,
          outcome: 'deny',
          reason: verdict.note ? `${decision.reason} — ${verdict.note}` : decision.reason,
        };
      }
    }

    if (decision.outcome !== 'allow') {
      this.stats.denied++;
      const receipt = this._record({ target, params, metrics, actor, decision: { ...decision, approval }, result: null });
      this.emit('denied', { target, decision, receipt });
      stdout.write(
        encode(
          toolRefusal(
            message.id,
            `Blocked by Proofwire policy. ${decision.reason}\n` +
              `Rules: ${decision.rules.join(', ') || 'none'}\n` +
              `This refusal is recorded as receipt ${receipt.seq} in log ${receipt.log}.`,
          ),
        ),
      );
      return;
    }

    // Allowed. The receipt is written *before* the call goes out, not after
    // the result comes back. Two reasons, both learned the hard way:
    //
    //   1. Budgets. Spend recorded on completion means three pipelined refunds
    //      all evaluate against an empty ledger and every one of them passes a
    //      cap they collectively blow through. Committing at decision time is
    //      the only accounting that holds under concurrency.
    //   2. Crashes. A process killed between the call and its reply would
    //      otherwise leave an action that really happened with no record that
    //      it ever did — precisely the gap this product exists to close.
    //
    // The result is recorded as a second, linked receipt when it arrives.
    const intent = this._record({
      target,
      params,
      metrics,
      actor,
      decision: { ...decision, approval },
      result: null,
      phase: 'intent',
    });

    this._pending.set(message.id, {
      target,
      params,
      metrics,
      actor,
      decision: { ...decision, approval },
      intentHash: entryHash(intent),
      startedAt: Date.now(),
    });
    this.stats.forwarded++;
    child.stdin.write(encode(message));
  }

  /**
   * @param {any} message
   * @param {NodeJS.WritableStream} stdout
   */
  _handleServerMessage(message, stdout) {
    if (isResponse(message) && this._pending.has(message.id)) {
      const call = this._pending.get(message.id);
      this._pending.delete(message.id);

      const failed = Boolean(message.error) || message.result?.isError === true;
      const receipt = this._record({
        ...call,
        // Metrics are deliberately omitted here: they were already committed
        // by the intent receipt, and counting them twice would halve every
        // budget.
        metrics: undefined,
        phase: 'outcome',
        ref: call.intentHash,
        result: {
          status: failed ? 'error' : 'ok',
          code: message.error?.code !== undefined ? String(message.error.code) : undefined,
          latencyMs: Date.now() - call.startedAt,
          payload: message.error ?? message.result,
        },
      });
      this.emit('recorded', { target: call.target, receipt });
    }
    stdout.write(encode(message));
  }

  /**
   * @param {object} args
   * @returns {import('@proofwire/core').Receipt}
   */
  _record(args) {
    const receipt = this.log.append({
      actor: args.actor,
      action: { kind: 'tool_call', target: args.target, params: args.params, metrics: args.metrics },
      decision: args.decision,
      result: args.result,
      phase: args.phase ?? 'atomic',
      ref: args.ref,
    });
    // Budgets and rate limits read from history, so it has to include the call
    // we just made — otherwise a burst of concurrent calls all see a stale
    // total and every one of them passes a cap they collectively blow through.
    this.history.push(receipt);
    return receipt;
  }

  /**
   * Flush anything still in flight when shutting down.
   *
   * A call we forwarded but never saw answered is not nothing: it is the most
   * interesting kind of gap, because it is exactly what an agent killed
   * mid-action looks like. It gets a receipt saying so.
   */
  finalize() {
    for (const [, call] of this._pending) {
      this._record({
        ...call,
        metrics: undefined,
        phase: 'outcome',
        ref: call.intentHash,
        result: { status: 'error', code: 'unfinished', latencyMs: Date.now() - call.startedAt, payload: null },
      });
    }
    this._pending.clear();
    if (this.log.size > 0) this.log.checkpoint();
  }
}
