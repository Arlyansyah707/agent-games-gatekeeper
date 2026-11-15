# vanderhaq-gatekeeper — Proof Gatekeeper agent for zkVerify Agent Games S01

Public HTTPS endpoint that answers Proof Gatekeeper tasks: it verifies the
signed task envelope, decides APPROVE/REJECT deterministically, and proves
the decision with a Groth16 proof from the tournament's own gatekeeper
circuit (BN254, Circom 2.x).

Live endpoint: `https://agent-games-theta.vercel.app/api/gatekeeper`

## How it decides (fail-closed)

Checks run in this order; the first failure rejects. A wrong approval costs
−6, a wrong rejection only −3, so any uncertainty rejects.

1. **VK_SUBSTITUTION** — the registered key must be the officially published
   verification-key hash, and the proof key must equal it. (A proof can
   verify with two equal-but-unregistered hashes — the circuit checks
   equality, not registered-ness — so this is checked off-circuit.)
2. **PROOF_REUSED** — the proof reference was already used in a previous
   competition task (persistent seen-set; no proof is generated — the
   tournament excludes reuse tasks from the proof requirement).
3. **EXPIRED_CONDITION** — `current_block > expiry_block` (equal is valid).
4. **THRESHOLD_MISMATCH** — `public_balance < minimum` (equal passes).
5. **RECIPIENT_MISMATCH** — recipient differs from the condition recipient
   (compared case-insensitively, matching the circuit's integer comparison).
6. **AMOUNT_OVERFLOW** — `amount > max_transfer` (equal passes).
7. Otherwise **APPROVE**.

Missing or malformed fields reject, mapped to the owning trap's reason code.
All numeric comparisons use arbitrary-precision integers.

## Proofs

Every provable decision carries a Groth16 proof (`proof` +
`public_signals`) generated with snarkjs 0.7.6 and the official circuit
files in `circuits/`. The circuit enforces
decision = approve ⟺ every check passes, so it arbitrates: if proving the
logic's decision fails, the opposite decision is tried once before falling
back to a proof-less REJECT. Proof generation takes ~0.3–1.6 s, far inside
the 60-second response window.

Retried task IDs return the byte-identical cached response. The seen-set
and response cache persist in a GitHub repo file (Contents API) so they
survive across serverless instances.

## Protocol

- `POST` — verify `x-agent-games-signature` (HMAC-SHA256 over the raw body)
  before parsing; bad signature → 401.
- Preflight / non-task POSTs and `GET` return
  `{"ok":true,"protocolVersion":"v1"}`, signed with the same HMAC.
- Task responses are signed the same way and stay under the 16 KB limit.

## Deploy

Vercel serverless function (`api/gatekeeper.js`, Node 22, `maxDuration: 60`).
Required env vars: `AGENT_HMAC_SECRET` (platform Rotate Secret),
`GITHUB_TOKEN`, `GITHUB_REPO`, `GITHUB_STATE_PATH`.
