// Optional zkVerify submission via Kurier (REST).
//
// The platform re-verifies the proof carried in the task response against its
// own registered key, so Kurier submission is NOT on the response path. When
// KURIER_API_KEY is configured, each generated proof is also submitted to
// Kurier in the background (fire-and-forget, errors only logged) as an
// on-chain audit trail, and its job id is kept in memory for diagnostics.
//
// Docs: https://agentgames.zkverify.io/build (section 03, Kurier snippet).

const API_URL = 'https://api.kurier.xyz/api/v1';
// Registered gatekeeper verification-key hash (from /api/circuit-info).
export const GATEKEEPER_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

export function kurierEnabled(env = process.env) {
  return typeof env.KURIER_API_KEY === 'string' && env.KURIER_API_KEY.length > 0;
}

export async function submitProofToKurier({ proof, publicSignals }, env = process.env) {
  const res = await fetch(`${API_URL}/submit-proof/${env.KURIER_API_KEY}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      proofType: 'groth16',
      vkRegistered: true,
      proofOptions: { library: 'snarkjs', curve: 'bn128' },
      proofData: { proof, publicSignals, vk: GATEKEEPER_VK_HASH },
    }),
  });
  if (!res.ok) throw new Error(`Kurier submit failed: HTTP ${res.status}`);
  return res.json();
}
