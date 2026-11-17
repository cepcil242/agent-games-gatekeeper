// Deterministic Proof Gatekeeper policy checks.
//
// The platform publishes seven task varieties: one valid condition and six
// traps (verification-key substitution, proof reused, threshold mismatch,
// expired condition, recipient mismatch, amount overflow). The decision is
// made here, in plain code — never by a language model — and the gatekeeper
// circuit independently enforces the five field checks, so a decision the
// circuit disagrees with cannot even produce a witness.
//
// Checks run in a fixed order; the first failure names the reason_code.

export const REASONS = {
  OK: 'OK',
  VK_SUBSTITUTION: 'VK_SUBSTITUTION',
  THRESHOLD_MISMATCH: 'THRESHOLD_MISMATCH',
  CONDITION_EXPIRED: 'CONDITION_EXPIRED',
  RECIPIENT_MISMATCH: 'RECIPIENT_MISMATCH',
  AMOUNT_OVERFLOW: 'AMOUNT_OVERFLOW',
  PROOF_REUSED: 'PROOF_REUSED',
  STALE_TASK: 'STALE_TASK',
  MALFORMED_TASK: 'MALFORMED_TASK',
  UNKNOWN_TASK_TYPE: 'UNKNOWN_TASK_TYPE',
};

const asBig = (v) => {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return BigInt(v);
  if (typeof v === 'string') return BigInt(v); // decimal or 0x-hex
  throw new TypeError(`not an integer value: ${String(v)}`);
};

const sameHex = (a, b) =>
  typeof a === 'string' && typeof b === 'string' &&
  a.toLowerCase() === b.toLowerCase();

/**
 * Evaluate one gatekeeper task input.
 * @param {object} input  the envelope's `input` object
 * @param {(proofTx: string) => boolean} isProofTxSeen  replay check
 * @returns {{decision: 'APPROVE'|'REJECT', reason_code: string}}
 */
export function evaluateGatekeeper(input, isProofTxSeen) {
  try {
    if (!input || typeof input !== 'object') {
      return { decision: 'REJECT', reason_code: REASONS.MALFORMED_TASK };
    }
    // 1. The proof must have been made under the key the condition registered.
    if (!sameHex(input.proof_vk, input.registered_vk)) {
      return { decision: 'REJECT', reason_code: REASONS.VK_SUBSTITUTION };
    }
    // 2. The disclosed balance must meet the condition's minimum.
    if (asBig(input.public_balance) < asBig(input.minimum)) {
      return { decision: 'REJECT', reason_code: REASONS.THRESHOLD_MISMATCH };
    }
    // 3. The condition must not have expired.
    if (asBig(input.current_block) > asBig(input.expiry_block)) {
      return { decision: 'REJECT', reason_code: REASONS.CONDITION_EXPIRED };
    }
    // 4. The money must go to the recipient the condition names.
    if (!sameHex(input.recipient, input.condition_recipient)) {
      return { decision: 'REJECT', reason_code: REASONS.RECIPIENT_MISMATCH };
    }
    // 5. The amount must stay within the condition's cap.
    if (asBig(input.amount) > asBig(input.max_transfer)) {
      return { decision: 'REJECT', reason_code: REASONS.AMOUNT_OVERFLOW };
    }
    // 6. A proof reference may be used for one task only (agent-side state;
    //    the circuit has no input for it, so this REJECT may carry no proof).
    if (typeof input.proof_tx === 'string' && isProofTxSeen(input.proof_tx)) {
      return { decision: 'REJECT', reason_code: REASONS.PROOF_REUSED };
    }
    return { decision: 'APPROVE', reason_code: REASONS.OK };
  } catch {
    // Any unparseable field is uncertainty: fail closed.
    return { decision: 'REJECT', reason_code: REASONS.MALFORMED_TASK };
  }
}

/**
 * Check the envelope's own freshness: issued in the past, deadline ahead.
 * Allows a small clock skew either way.
 */
export function envelopeFresh(envelope, now = Date.now(), skewMs = 30_000) {
  const issued = Date.parse(envelope.issued_at ?? '');
  const deadline = Date.parse(envelope.deadline_at ?? '');
  if (Number.isNaN(issued) || Number.isNaN(deadline)) return false;
  if (issued > now + skewMs) return false;
  if (deadline < now - skewMs) return false;
  return true;
}
