#!/usr/bin/env node
/**
 * A minimal MCP stdio server, used by the demo and the proxy tests.
 *
 * It implements just enough of the protocol to be a realistic thing to wrap:
 * initialize, tools/list, tools/call, and a notification it ignores. The tools
 * are the kind that make people nervous about agents — moving money, sending
 * mail, running SQL — because those are the ones worth having receipts for.
 */

import { createInterface } from 'node:readline';

const TOOLS = [
  {
    name: 'refund',
    description: 'Issue a refund against an order.',
    inputSchema: {
      type: 'object',
      properties: {
        order: { type: 'string' },
        amount: { type: 'number', description: 'Amount in cents' },
      },
      required: ['order', 'amount'],
    },
  },
  {
    name: 'send_email',
    description: 'Send an email to a customer.',
    inputSchema: {
      type: 'object',
      properties: { to: { type: 'string' }, subject: { type: 'string' }, body: { type: 'string' } },
      required: ['to', 'subject'],
    },
  },
  {
    name: 'query',
    description: 'Run a read-only SQL query.',
    inputSchema: {
      type: 'object',
      properties: { sql: { type: 'string' } },
      required: ['sql'],
    },
  },
];

/** @param {unknown} msg */
function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

/**
 * @param {string} name
 * @param {Record<string, any>} a
 */
function callTool(name, a) {
  switch (name) {
    case 'refund':
      return { content: [{ type: 'text', text: `Refunded ${a.amount} cents on ${a.order}. id=re_${Math.random().toString(36).slice(2, 10)}` }] };
    case 'send_email':
      return { content: [{ type: 'text', text: `Sent "${a.subject}" to ${a.to}.` }] };
    case 'query':
      if (/drop|delete|truncate/i.test(a.sql ?? '')) {
        // The upstream server would happily run it. That is the point: the
        // guardrail cannot live here, in the thing being guarded.
        return { content: [{ type: 'text', text: 'Statement executed. 4,812 rows affected.' }] };
      }
      return { content: [{ type: 'text', text: '{"rows":[{"count":128}]}' }] };
    default:
      return { content: [{ type: 'text', text: `No such tool: ${name}` }], isError: true };
  }
}

createInterface({ input: process.stdin, terminal: false }).on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.id === undefined || msg.id === null) return; // notification

  switch (msg.method) {
    case 'initialize':
      return send({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'fake-ops-server', version: '1.0.0' },
        },
      });
    case 'tools/list':
      return send({ jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } });
    case 'tools/call':
      return send({
        jsonrpc: '2.0',
        id: msg.id,
        result: callTool(msg.params?.name, msg.params?.arguments ?? {}),
      });
    default:
      return send({
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32601, message: `Method not found: ${msg.method}` },
      });
  }
});
