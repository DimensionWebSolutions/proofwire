#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { Hub, DEFAULT_CONFIG } from './app.js';
import { Auth } from './auth.js';

/**
 * Hub entry point.
 *
 *   proofwire-hub serve                 start the server
 *   proofwire-hub bootstrap             create the first org, admin and keys
 *   proofwire-hub check                 verify every stored log
 *
 * Configuration is environment-only. A hub reads secrets and binds ports; a
 * config file that can be edited by whoever can reach the filesystem is one
 * more thing to get wrong in a container.
 */

/** @returns {Partial<typeof DEFAULT_CONFIG>} */
function configFromEnv() {
  const env = process.env;
  /** @type {any} */
  const config = {};
  if (env.PROOFWIRE_PORT) config.port = Number(env.PROOFWIRE_PORT);
  if (env.PROOFWIRE_HOST) config.host = env.PROOFWIRE_HOST;
  if (env.PROOFWIRE_DB) config.database = env.PROOFWIRE_DB;
  if (env.PROOFWIRE_PUBLIC_URL) config.publicUrl = env.PROOFWIRE_PUBLIC_URL;
  // Only honour X-Forwarded-For when explicitly told to: behind no proxy, it
  // is a header any client can set to evade a per-address rate limit.
  if (env.PROOFWIRE_TRUST_PROXY === '1') config.trustProxy = true;
  if (env.PROOFWIRE_CHECKPOINT_EVERY) config.checkpointEvery = Number(env.PROOFWIRE_CHECKPOINT_EVERY);
  if (env.PROOFWIRE_APPROVAL_TTL) config.approvalTtlSeconds = Number(env.PROOFWIRE_APPROVAL_TTL);
  return config;
}

const B = (s) => `[1m${s}[0m`;
const DIM = (s) => `[90m${s}[0m`;
const GREEN = (s) => `[32m${s}[0m`;
const RED = (s) => `[31m${s}[0m`;
const CYAN = (s) => `[36m${s}[0m`;

async function serve() {
  const hub = new Hub(configFromEnv());
  const { url } = await hub.listen();

  console.error('');
  console.error(B('  Proofwire hub') + DIM('  0.2.0'));
  console.error(DIM(`  ${url}`));
  console.error(DIM(`  db       ${hub.config.database}`));
  console.error(DIM(`  hub key  ${hub.hubIdentity.kid}`));
  console.error(DIM(`  witness  ${hub.witnessIdentity.kid}`));
  console.error('');

  // A hub that never re-reads its own storage is taking itself at its word.
  // Re-verifying every log on a schedule is cheap and is the difference
  // between detecting silent corruption in an hour and in a deposition.
  const interval = Number(process.env.PROOFWIRE_SELFCHECK_MINUTES ?? 60);
  if (interval > 0) {
    const timer = setInterval(() => {
      for (const org of hub.db.prepare('SELECT id FROM orgs').all()) {
        for (const log of hub.store.logs(org.id)) {
          const res = hub.store.audit(org.id, log.id);
          if (!res.ok) {
            console.error(
              JSON.stringify({
                level: 'error',
                event: 'selfcheck.failed',
                org: org.id,
                log: log.slug,
                issues: res.issues.slice(0, 5),
              }),
            );
          }
        }
      }
    }, interval * 60_000);
    timer.unref();
  }

  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, async () => {
      console.error(DIM('\n  shutting down…'));
      await hub.close();
      process.exit(0);
    });
  }
}

/**
 * Create the first organization, an admin who can sign in, and the two API
 * keys a deployment actually needs on day one.
 */
async function bootstrap() {
  const hub = new Hub(configFromEnv());
  const auth = new Auth(hub.store);

  const orgName = process.env.PROOFWIRE_ORG ?? 'Acme';
  const slug = (process.env.PROOFWIRE_ORG_SLUG ?? orgName).toLowerCase().replace(/[^a-z0-9-]+/g, '-');
  const email = process.env.PROOFWIRE_ADMIN_EMAIL ?? 'admin@example.com';
  const password = process.env.PROOFWIRE_ADMIN_PASSWORD ?? randomBytes(9).toString('base64url');

  if (hub.store.orgBySlug(slug)) {
    console.error(RED(`  an organization "${slug}" already exists`));
    await hub.close();
    process.exitCode = 1;
    return;
  }

  const org = hub.store.createOrg({ slug, name: orgName });
  const user = auth.userByEmail(email) ?? auth.createUser({ email, password });
  auth.addMember(org.id, user.id, 'owner');

  const agentKey = auth.createKey({
    orgId: org.id,
    name: 'agent-runtime',
    scopes: ['receipts:write', 'logs:write', 'logs:read', 'policies:read'],
    createdBy: 'bootstrap',
  });
  const auditKey = auth.createKey({
    orgId: org.id,
    name: 'auditor-readonly',
    scopes: ['receipts:read', 'logs:read', 'policies:read', 'approvals:read'],
    createdBy: 'bootstrap',
  });

  hub.store.recordEvent({
    orgId: org.id,
    actor: 'bootstrap',
    actorKind: 'system',
    action: 'org.create',
    subject: org.slug,
  });

  console.error('');
  console.error(B('  Organization created'));
  console.error(DIM('  ─────────────────────────────────────────────'));
  console.error(`  org        ${org.slug}  ${DIM(org.id)}`);
  console.error(`  admin      ${email}`);
  console.error(`  password   ${B(password)}`);
  console.error('');
  console.error(B('  API keys') + DIM('  (shown once — they are not stored in recoverable form)'));
  console.error(`  agent      ${CYAN(agentKey.token)}`);
  console.error(DIM('             receipts:write logs:write logs:read policies:read'));
  console.error(`  auditor    ${CYAN(auditKey.token)}`);
  console.error(DIM('             read-only: the credential to hand an outside firm'));
  console.error('');
  console.error(DIM('  Point an agent at it:'));
  console.error(`    ${CYAN(`pw remote add --url http://localhost:${hub.config.port} --token <agent token>`)}`);
  console.error('');

  await hub.close();
}

/** Verify every stored log and exit non-zero if any fails. */
async function check() {
  const hub = new Hub(configFromEnv());
  let bad = 0;
  let total = 0;

  for (const org of hub.db.prepare('SELECT * FROM orgs').all()) {
    for (const log of hub.store.logs(org.id)) {
      total++;
      const res = hub.store.audit(org.id, log.id);
      const label = `${org.slug}/${log.slug}`.padEnd(34);
      if (res.ok) {
        console.log(`  ${GREEN('✓')} ${label} ${DIM(`${res.size} entries · ${res.root.slice(0, 16)}…`)}`);
      } else {
        bad++;
        console.log(`  ${RED('✗')} ${label} ${RED(`${res.issues.length} problem(s)`)}`);
        for (const i of res.issues.slice(0, 5)) console.log(`      ${DIM(i.message)}`);
      }
    }
    const events = hub.store.auditEvents(org.id);
    if (!events.ok) {
      bad++;
      console.log(`  ${RED('✗')} ${org.slug}: control-plane audit chain broken`);
    }
  }

  console.log('');
  console.log(bad === 0 ? `  ${GREEN(`All ${total} log(s) verify.`)}` : `  ${RED(`${bad} of ${total} failed.`)}`);
  await hub.close();
  process.exitCode = bad === 0 ? 0 : 1;
}

const command = process.argv[2] ?? 'serve';
const COMMANDS = { serve, bootstrap, check };

if (!COMMANDS[command]) {
  console.error(`unknown command "${command}" — try: ${Object.keys(COMMANDS).join(', ')}`);
  process.exitCode = 2;
} else {
  await COMMANDS[command]();
}
