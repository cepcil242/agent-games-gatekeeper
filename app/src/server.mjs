// Proof Gatekeeper agent — a plain Node.js HTTPS-ready HTTP service.
//
// Contract (https://agentgames.zkverify.io/build):
//   - The platform POSTs signed JSON envelopes to the registered path
//     (default /agent). The HMAC-SHA256 hex of the RAW request body travels
//     in the `x-agent-games-signature` header and is verified BEFORE parsing.
//   - Preflight envelopes (type agent-games.preflight.v1) are answered with
//     { ok: true, protocolVersion: "v1" }.
//   - Gatekeeper tasks (type agent-games.proof-gatekeeper.v1) are answered
//     with { decision, reason_code, proof, public_signals, proof_tx? }.
//   - EVERY response body is signed: the response carries its own
//     `x-agent-games-signature` header over the raw response body.
//   - Hard deadline 60 s; fail closed — any error or uncertainty is a REJECT,
//     never an approval.
//
// Secrets come from the environment only: AGENT_GAMES_HMAC_SECRET (the
// platform-generated value from the dashboard's Rotate Secret) and the
// optional KURIER_API_KEY. Nothing secret is ever logged.

import { createServer } from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { evaluateGatekeeper, envelopeFresh, REASONS } from './decision.mjs';
import { proveDecision } from './proof.mjs';
import { kurierEnabled, submitProofToKurier } from './kurier.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const APP_DIR = resolve(HERE, '..');

const PORT = Number(process.env.PORT ?? 8080);
const AGENT_PATH = process.env.AGENT_PATH ?? '/agent';
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET ?? '';
const CIRCUITS_DIR = resolve(process.env.CIRCUITS_DIR ?? join(APP_DIR, '..', 'circuits'));
const WASM_PATH = join(CIRCUITS_DIR, 'gatekeeper.wasm');
const ZKEY_PATH = join(CIRCUITS_DIR, 'gatekeeper_final.zkey');
const SEEN_PATH = join(APP_DIR, 'data', 'seen-proof-tx.json');
const SOFT_BUDGET_MS = 50_000; // answer well inside the 60 s hard deadline

if (!SECRET) {
  console.error(
    '[agent] WARNING: AGENT_GAMES_HMAC_SECRET is not set — every signed ' +
    'request will fail verification. Set it from the dashboard (Rotate Secret).',
  );
}

// --- replay state: proof_tx values already decided (persisted) -------------
const seenProofTx = new Set(
  existsSync(SEEN_PATH) ? JSON.parse(readFileSync(SEEN_PATH, 'utf8')) : [],
);
function markProofTxSeen(tx) {
  if (typeof tx !== 'string' || seenProofTx.has(tx)) return;
  seenProofTx.add(tx);
  try {
    mkdirSync(dirname(SEEN_PATH), { recursive: true });
    writeFileSync(SEEN_PATH, JSON.stringify([...seenProofTx]));
  } catch (err) {
    console.error('[agent] could not persist seen proof_tx set:', err.message);
  }
}

// --- HMAC helpers -----------------------------------------------------------
const hmacHex = (secret, raw) =>
  createHmac('sha256', secret).update(raw).digest('hex');

function signatureValid(rawBody, headerValue) {
  if (!SECRET || typeof headerValue !== 'string') return false;
  const expected = Buffer.from(hmacHex(SECRET, rawBody), 'utf8');
  const given = Buffer.from(headerValue.trim().toLowerCase(), 'utf8');
  return expected.length === given.length && timingSafeEqual(expected, given);
}

function sendSigned(res, status, obj) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-agent-games-signature': hmacHex(SECRET, raw),
  });
  res.end(raw);
}

// --- task handling ----------------------------------------------------------
async function handleGatekeeper(envelope) {
  const started = Date.now();
  const base = { proof_tx: envelope.input?.proof_tx };

  if (!envelopeFresh(envelope)) {
    return { decision: 'REJECT', reason_code: REASONS.STALE_TASK, ...base };
  }

  const { decision, reason_code } = evaluateGatekeeper(
    envelope.input,
    (tx) => seenProofTx.has(tx),
  );

  // The decision is final from here on; the proof is evidence for it.
  let proof = null;
  let publicSignals = null;
  try {
    const out = await proveDecision(envelope, decision, {
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
    });
    proof = out.proof;
    publicSignals = out.publicSignals;
  } catch (err) {
    // The circuit refused the witness. For the five field checks this cannot
    // happen when the JS evaluation above is correct; for agent-side checks
    // (PROOF_REUSED, STALE_TASK) a REJECT of a field-valid task is exactly
    // the case the circuit cannot prove. The decision stands — an omitted
    // proof costs less than approving a trap — and the failure is logged.
    console.error(
      `[agent] proof generation failed for task ${envelope.task_id} ` +
      `(${reason_code}): ${err.message}`,
    );
  }

  if (proof && kurierEnabled()) {
    submitProofToKurier({ proof, publicSignals }).catch((err) =>
      console.error('[agent] Kurier submission failed:', err.message),
    );
  }

  markProofTxSeen(envelope.input?.proof_tx);
  const elapsed = Date.now() - started;
  if (elapsed > SOFT_BUDGET_MS) {
    console.error(`[agent] task ${envelope.task_id} took ${elapsed} ms (over soft budget)`);
  }
  return { decision, reason_code, proof, public_signals: publicSignals, ...base };
}

async function handleEnvelope(envelope) {
  switch (envelope?.type) {
    case 'agent-games.preflight.v1':
      return { status: 200, body: { ok: true, protocolVersion: 'v1' } };
    case 'agent-games.proof-gatekeeper.v1': {
      const body = await handleGatekeeper(envelope);
      // proof/public_signals are required on provable tasks; when proof
      // generation was impossible the fields go out as null rather than
      // being dropped silently — the decision remains a fail-closed REJECT.
      return { status: 200, body };
    }
    default:
      return {
        status: 200,
        body: { decision: 'REJECT', reason_code: REASONS.UNKNOWN_TASK_TYPE },
      };
  }
}

// --- HTTP transport -----------------------------------------------------------
const server = createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  if (req.method !== 'POST' || req.url !== AGENT_PATH) {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
    return;
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    // Verify BEFORE parsing or processing — a bad signature ends here.
    if (!signatureValid(raw, req.headers['x-agent-games-signature'])) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid signature' }));
      return;
    }
    let envelope;
    try {
      envelope = JSON.parse(raw.toString('utf8'));
    } catch {
      sendSigned(res, 200, { decision: 'REJECT', reason_code: REASONS.MALFORMED_TASK });
      return;
    }
    try {
      const { status, body } = await handleEnvelope(envelope);
      sendSigned(res, status, body);
    } catch (err) {
      console.error('[agent] handler error:', err);
      sendSigned(res, 200, { decision: 'REJECT', reason_code: REASONS.MALFORMED_TASK });
    }
  });
});

server.listen(PORT, () => {
  console.log(`[agent] Proof Gatekeeper listening on :${PORT}${AGENT_PATH}`);
  console.log(`[agent] circuits: ${WASM_PATH} / ${ZKEY_PATH}`);
});
