// Local test harness: starts the agent with a throwaway secret, replays
// signed sample envelopes (the /build page's example values), and checks
// decisions, response signatures, and local Groth16 proof verification.
//
//   node test.mjs
//
// Uses a scratch PORT and a temp seen-store so runs never touch real state.

import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const PORT = 18099;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'test-secret-for-local-harness-only';
const VK = JSON.parse(readFileSync(join(ROOT, 'circuits', 'gatekeeper_vk.json'), 'utf8'));

const sign = (raw) => createHmac('sha256', SECRET).update(raw).digest('hex');

async function post(path, obj, { secret = SECRET } = {}) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': createHmac('sha256', secret).update(raw).digest('hex'),
    },
    body: raw,
  });
  const text = await res.text();
  return { status: res.status, sig: res.headers.get('x-agent-games-signature'), body: text ? JSON.parse(text) : null, raw: text };
}

const now = Date.now();
const iso = (ms) => new Date(ms).toISOString();
// The /build page's sample values; registered_vk/proof_vk are stand-in
// 32-byte hashes here (a real task carries the condition's own values).
const VK_A = '0x7d3f5a91c2e44b08a6d1f05c93b8274e6a0d19f3852c47a09be6135d48f7291aa';
const VK_B = '0x13aa04d77c51b9e2f083ad619c52e047bb93d18f6a24c095e3d71f48a05c62bb';
const ADDR = '0xDe42a91B04c77E53dA81F09b26C43e57A1c9f01';

function envelope(overrides = {}, inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: `gk_test_${Math.random().toString(36).slice(2, 9)}`,
    mode: 'practice',
    issued_at: iso(now - 5_000),
    deadline_at: iso(now + 55_000),
    input: {
      registered_vk: VK_A,
      proof_vk: VK_A,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xa8' + Math.random().toString(16).slice(2, 10) + '2c',
      ...inputOverrides,
    },
    ...overrides,
  };
}

let failures = 0;
function check(name, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
  if (!cond) failures++;
}

async function expectDecision(name, env, decision, reason) {
  const r = await post('/agent', env);
  check(`${name}: HTTP 200`, r.status === 200);
  check(`${name}: decision ${decision}`, r.body?.decision === decision, `got ${r.body?.decision}/${r.body?.reason_code}`);
  if (reason) check(`${name}: reason ${reason}`, r.body?.reason_code === reason);
  check(`${name}: response signature valid`, r.sig === sign(r.raw));
  if (r.body?.proof) {
    check(`${name}: 13 public signals`, r.body.public_signals?.length === 13);
    const ok = await snarkjs.groth16.verify(VK, r.body.public_signals, r.body.proof);
    check(`${name}: proof verifies locally`, ok === true);
  } else {
    console.log(`      (${name}: no proof attached)`);
  }
  return r;
}

async function main() {
  rmSync(join(HERE, 'data'), { recursive: true, force: true });
  const child = spawn('node', ['src/server.mjs'], {
    cwd: HERE,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, CIRCUITS_DIR: join(ROOT, 'circuits') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));
  try {
    // wait for health
    for (let i = 0; i < 50; i++) {
      try { const h = await fetch(`${BASE}/healthz`); if (h.ok) break; } catch {}
      await new Promise((r) => setTimeout(r, 200));
    }

    // Preflight
    const pf = await post('/agent', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: iso(now), nonce: 'abc123' });
    check('preflight: ok true', pf.body?.ok === true);
    check('preflight: protocolVersion v1', pf.body?.protocolVersion === 'v1');
    check('preflight: response signature valid', pf.sig === sign(pf.raw));

    // Bad signature is refused before anything else
    const bad = await post('/agent', envelope(), { secret: 'wrong-secret' });
    check('bad signature: HTTP 401', bad.status === 401);

    // The trap matrix (sample values from /build)
    await expectDecision('valid task', envelope(), 'APPROVE', 'OK');
    await expectDecision('vk substitution', envelope({}, { proof_vk: VK_B }), 'REJECT', 'VK_SUBSTITUTION');
    await expectDecision('below minimum', envelope({}, { public_balance: '900' }), 'REJECT', 'THRESHOLD_MISMATCH');
    await expectDecision('expired', envelope({}, { current_block: 8440000 }), 'REJECT', 'CONDITION_EXPIRED');
    await expectDecision('recipient mismatch', envelope({}, { recipient: '0x1111111111111111111111111111111111111111' }), 'REJECT', 'RECIPIENT_MISMATCH');
    await expectDecision('amount overflow', envelope({}, { amount: '1500' }), 'REJECT', 'AMOUNT_OVERFLOW');

    // Reused proof_tx: same tx twice — the second must be PROOF_REUSED.
    const sharedTx = '0xa8deadbeef2c';
    await expectDecision('first use of proof_tx', envelope({}, { proof_tx: sharedTx }), 'APPROVE', 'OK');
    await expectDecision('reused proof_tx', envelope({}, { proof_tx: sharedTx }), 'REJECT', 'PROOF_REUSED');

    // Stale envelope
    await expectDecision('stale task', envelope({ deadline_at: iso(now - 60_000) }), 'REJECT', 'STALE_TASK');
  } finally {
    child.kill('SIGTERM');
    rmSync(join(HERE, 'data'), { recursive: true, force: true });
  }
  console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => { console.error(err); process.exit(1); });
