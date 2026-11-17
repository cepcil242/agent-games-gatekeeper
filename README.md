# Agent Games — Proof Gatekeeper agent

An agent for the zkVerify **Agent Games** (Season 01, Proof Gatekeeper
track), built to the contract at https://agentgames.zkverify.io/build.

The platform POSTs signed task envelopes to the agent's public HTTPS
endpoint. For each transfer request the agent decides APPROVE or REJECT with
deterministic checks, generates a Groth16 proof of the decision locally with
snarkjs and the official gatekeeper circuit, and returns a signed response —
inside the platform's 60-second deadline, failing closed on any doubt.

## Layout

- `circuits/` — official artifacts (`gatekeeper.wasm`,
  `gatekeeper_final.zkey`, hashes verified against `/api/circuit-info`) and
  the exported `gatekeeper_vk.json` (Groth16/BN128, 13 public inputs).
- `app/src/server.mjs` — HTTP transport: HMAC verification of the raw body
  before parsing, preflight responder, signed responses.
- `app/src/decision.mjs` — the policy checks in fixed order: VK substitution,
  threshold, expiry, recipient, amount cap, proof-tx replay, task freshness.
- `app/src/proof.mjs` — circuit input encoding (keccak256-based taskId and
  VK-hash field elements, plain-integer addresses, private random salt) and
  proof generation.
- `app/src/kurier.mjs` — optional background proof submission to zkVerify
  via Kurier (only when `KURIER_API_KEY` is set; never on the response path).
- `app/test.mjs` — local harness: replays the /build sample values through
  the full trap matrix and verifies every returned proof locally.

## Run

```sh
cd app
npm install
AGENT_GAMES_HMAC_SECRET=<from the dashboard's Rotate Secret> npm start
# listens on :8080/agent  (PORT, AGENT_PATH, CIRCUITS_DIR via env)
npm test   # local end-to-end trap matrix with a throwaway secret
```

## Deploy checklist

1. Host `app/` somewhere with a public HTTPS URL (the platform posts to the
   URL exactly as registered — register the full path, e.g.
   `https://<host>/agent`).
2. Set `AGENT_GAMES_HMAC_SECRET` in the host's environment to the
   platform-generated value (dashboard → Rotate Secret, shown once). Paste
   it into the host's env settings directly — never through a chat.
3. Register the endpoint URL on the dashboard, then let the platform's
   preflight run; it must pass before the agent is marked active.
4. Optional: set `KURIER_API_KEY` for background proof submission.

## Known limits

- A REJECT for proof-tx replay (or a stale envelope) cannot carry a circuit
  proof: the circuit's own evaluation of the five field checks is "approve"
  for such tasks, so it refuses a reject witness (assert at
  GatekeeperEvaluation_79:102 — confirmed locally). The decision still goes
  out, signed, without a proof: an omitted proof (−2) beats approving a
  trap (−6).
- Field encodings follow the circuit's recovered ABI (13 inputs; taskId and
  VK hashes as keccak/integer values reduced mod the BN254 prime). The five
  decision checks are encoding-invariant, but the platform's public-signal
  comparison is the one thing local tests cannot rehearse — the first live
  practice tasks are the real check.
