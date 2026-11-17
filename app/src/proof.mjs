// Groth16 proof generation for the gatekeeper circuit (Circom 2.x, BN128),
// using the official artifacts from https://agentgames.zkverify.io/circuits/.
//
// Circuit inputs (13; recovered from the compiled WASM's FNV-1a signal table
// and confirmed against the exported verification key, which has 13 public
// inputs):
//   taskId, minimum, publicBalance, expiryBlock, currentBlock, recipient,
//   conditionRecipient, amount, maxTransfer, registeredVkHash, proofVkHash,
//   salt (the only private input), decision (1 = APPROVE, 0 = REJECT).
//
// Encodings (field = BN254 scalar field):
//   - taskId:           keccak256(utf8(task_id)) mod p
//   - registeredVkHash: integer(registered_vk) mod p   (the value is a hash)
//   - proofVkHash:      integer(proof_vk) mod p
//   - recipient etc.:   plain integer of the address
//   - amounts/blocks:   the integers as given
//   - salt:             a fresh random 32-byte value mod p, never revealed
//
// snarkjs returns publicSignals in the circuit's own order: a salt-dependent
// binding commitment first, then the twelve public inputs. They are passed
// through verbatim.

import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { keccak256 } from 'js-sha3';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');

export const FIELD_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const modP = (x) => ((x % FIELD_P) + FIELD_P) % FIELD_P;
const intOf = (v) => (typeof v === 'string' || typeof v === 'number' ? BigInt(v) : v);

export function taskIdToField(taskId) {
  return modP(BigInt('0x' + keccak256(new TextEncoder().encode(String(taskId)))));
}

export function hashToField(hexHash) {
  return modP(BigInt(hexHash));
}

export function buildCircuitInput(envelope, decision /* 'APPROVE' | 'REJECT' */) {
  const input = envelope.input;
  const salt = modP(BigInt('0x' + randomBytes(32).toString('hex')));
  return {
    taskId: taskIdToField(envelope.task_id).toString(),
    minimum: intOf(input.minimum).toString(),
    publicBalance: intOf(input.public_balance).toString(),
    expiryBlock: intOf(input.expiry_block).toString(),
    currentBlock: intOf(input.current_block).toString(),
    recipient: intOf(input.recipient).toString(),
    conditionRecipient: intOf(input.condition_recipient).toString(),
    amount: intOf(input.amount).toString(),
    maxTransfer: intOf(input.max_transfer).toString(),
    registeredVkHash: hashToField(input.registered_vk).toString(),
    proofVkHash: hashToField(input.proof_vk).toString(),
    salt: salt.toString(),
    decision: decision === 'APPROVE' ? '1' : '0',
  };
}

/**
 * Generate the proof for a decided task.
 * Throws when the circuit refuses the witness — i.e. when the decision does
 * not match the circuit's own evaluation of the five field checks. Callers
 * treat that as "decision stands, proof unavailable" (see server).
 */
export async function proveDecision(envelope, decision, { wasmPath, zkeyPath }) {
  const circuitInput = buildCircuitInput(envelope, decision);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    wasmPath,
    zkeyPath,
  );
  return { proof, publicSignals };
}

/** Local verification against the exported verification key (tests/health). */
export async function verifyProofLocally(vkJson, proof, publicSignals) {
  return snarkjs.groth16.verify(vkJson, publicSignals, proof);
}
