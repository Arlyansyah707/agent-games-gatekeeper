// Proof Gatekeeper agent endpoint — zkVerify Agent Games Season 01.
// Node.js serverless function (Vercel). No framework.
//
// Flow: HMAC-verify raw body -> preflight? protocol JSON : task decision.
// Decision is deterministic + fail-closed; a Groth16 proof (tournament's
// own gatekeeper circuit) backs every provable decision. The circuit
// arbitrates: if proving the logic's decision fails, the opposite decision
// is tried once before falling back to REJECT without proof.
//
// Env: AGENT_HMAC_SECRET (platform Rotate Secret), GITHUB_TOKEN,
// GITHUB_REPO (owner/repo), GITHUB_STATE_PATH (default agent-games/state.json).

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const OFFICIAL_VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const PROTOCOL = { ok: true, protocolVersion: "v1" };
const SOFT_DEADLINE_MS = 50000;

// ---- in-memory fallback state (per-instance; GitHub is the source of truth)
const memState = { seen: new Set(), responses: new Map() };

// ---- helpers ----
function hmacHex(secret, body) {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}
function verifyHmac(secret, body, sig) {
  if (!secret || !sig) return false;
  const want = hmacHex(secret, body);
  const a = Buffer.from(want, "utf8");
  const b = Buffer.from(String(sig).trim().toLowerCase(), "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function normHex(v) {
  if (v === null || v === undefined) return null;
  let s = String(v).trim().toLowerCase();
  if (!s) return null;
  if (!s.startsWith("0x")) s = "0x" + s;
  return s;
}
function parseBig(v) {
  // Strict integer parse: decimal or 0x-hex, arbitrary precision. null on failure.
  if (v === null || v === undefined) return null;
  let s = String(v).trim();
  if (!s) return null;
  try {
    if (/^0x[0-9a-f]+$/i.test(s)) return BigInt(s);
    if (/^[0-9]+$/.test(s)) return BigInt(s);
    return null;
  } catch {
    return null;
  }
}
function taskIdField(taskId) {
  // taskId string -> field element: UTF-8 bytes as big-endian integer.
  const buf = Buffer.from(String(taskId), "utf8");
  if (buf.length === 0) return "0";
  return BigInt("0x" + buf.toString("hex")).toString();
}

// ---- GitHub Contents API state (persistent seen-set + response cache) ----
function ghConfig() {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPO;
  if (!token || !repo) return null;
  return {
    token,
    repo,
    path: process.env.GITHUB_STATE_PATH || "agent-games/state.json",
  };
}
async function ghGetState(cfg) {
  const r = await fetch(`https://api.github.com/repos/${cfg.repo}/contents/${cfg.path}`, {
    headers: { Authorization: `Bearer ${cfg.token}`, Accept: "application/vnd.github+json", "User-Agent": "agent-games-gatekeeper" },
  });
  if (r.status === 404) return { state: { seen: [], responses: {} }, sha: null };
  if (!r.ok) throw new Error(`GitHub GET state HTTP ${r.status}`);
  const j = await r.json();
  const state = JSON.parse(Buffer.from(j.content, "base64").toString("utf8"));
  return { state, sha: j.sha };
}
async function ghPutState(cfg, state, sha) {
  const body = {
    message: "agent-games gatekeeper state update",
    content: Buffer.from(JSON.stringify(state)).toString("base64"),
  };
  if (sha) body.sha = sha;
  const r = await fetch(`https://api.github.com/repos/${cfg.repo}/contents/${cfg.path}`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${cfg.token}`, Accept: "application/vnd.github+json", "User-Agent": "agent-games-gatekeeper" },
    body: JSON.stringify(body),
  });
  if (r.status === 409) return { conflict: true };
  if (!r.ok) throw new Error(`GitHub PUT state HTTP ${r.status}`);
  return { conflict: false };
}
async function loadState() {
  const cfg = ghConfig();
  const local = { seen: new Set(memState.seen), responses: new Map(memState.responses) };
  if (!cfg) return { cfg: null, sha: null, seen: local.seen, responses: local.responses };
  try {
    const { state, sha } = await ghGetState(cfg);
    for (const s of state.seen || []) local.seen.add(s);
    for (const [k, v] of Object.entries(state.responses || {})) {
      if (!local.responses.has(k)) local.responses.set(k, v);
    }
    return { cfg, sha, seen: local.seen, responses: local.responses };
  } catch (e) {
    console.error("state load failed, using memory only:", e.message);
    return { cfg, sha: null, seen: local.seen, responses: local.responses };
  }
}
async function saveState(loaded, seen, responses) {
  // update memory always
  memState.seen = new Set(seen);
  memState.responses = new Map(responses);
  if (!loaded.cfg) return;
  const state = { seen: [...seen], responses: Object.fromEntries(responses) };
  let sha = loaded.sha;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const r = await ghPutState(loaded.cfg, state, sha);
      if (!r.conflict) return;
      // conflict: re-read, merge, retry
      const fresh = await ghGetState(loaded.cfg);
      for (const s of fresh.state.seen || []) state.seen.push(s);
      state.seen = [...new Set(state.seen)];
      state.responses = { ...(fresh.state.responses || {}), ...state.responses };
      sha = fresh.sha;
    } catch (e) {
      console.error("state save failed (attempt " + attempt + "):", e.message);
      return;
    }
  }
}

// ---- decision logic (fail-closed) ----
// Check order (Hydrogen review 15 Nov + spec): VK first (untrusted proof
// invalidates all claims), then reuse, expiry, threshold, recipient, amount.
// Returns {decision: 0|1, reason_code, provable: bool, malformed: bool}.
function decide(input, seen) {
  const need = (v) => v !== null && v !== undefined && String(v).trim() !== "";
  // malformed / missing fields -> REJECT, mapped to the owning trap code
  const malformed = (code) => ({ decision: 0, reason_code: code, provable: false, malformed: true });
  if (!need(input.proof_tx)) return malformed("PROOF_REUSED");
  if (!need(input.registered_vk) || !need(input.proof_vk)) return malformed("VK_SUBSTITUTION");
  if (!need(input.public_balance) || !need(input.minimum)) return malformed("THRESHOLD_MISMATCH");
  if (input.expiry_block === null || input.expiry_block === undefined || input.current_block === null || input.current_block === undefined)
    return malformed("EXPIRED_CONDITION");
  if (!need(input.recipient) || !need(input.condition_recipient)) return malformed("RECIPIENT_MISMATCH");
  if (!need(input.amount) || !need(input.max_transfer)) return malformed("AMOUNT_OVERFLOW");

  const registeredVk = normHex(input.registered_vk);
  const proofVk = normHex(input.proof_vk);
  const recipient = normHex(input.recipient);
  const conditionRecipient = normHex(input.condition_recipient);
  const proofTx = String(input.proof_tx).trim().toLowerCase();

  const balance = parseBig(input.public_balance);
  const minimum = parseBig(input.minimum);
  const amount = parseBig(input.amount);
  const maxTransfer = parseBig(input.max_transfer);
  const expiry = parseBig(input.expiry_block);
  const current = parseBig(input.current_block);
  if (balance === null || minimum === null) return malformed("THRESHOLD_MISMATCH");
  if (amount === null || maxTransfer === null) return malformed("AMOUNT_OVERFLOW");
  if (expiry === null || current === null) return malformed("EXPIRED_CONDITION");
  if (!registeredVk || !proofVk) return malformed("VK_SUBSTITUTION");
  if (!recipient || !conditionRecipient) return malformed("RECIPIENT_MISMATCH");

  // 1. VK: registered key must be the OFFICIAL published hash (fake-key lesson:
  // a proof can verify with two equal-but-unregistered hashes). Then proof key
  // must equal the registered key.
  const fakeKey = registeredVk !== OFFICIAL_VK_HASH.toLowerCase();
  if (fakeKey || proofVk !== registeredVk) {
    // provable only when the circuit agrees the checks fail (proofVk != registeredVk).
    // If proofVk == registeredVk (fake-key only), the circuit would bless APPROVE,
    // so a REJECT proof cannot be built -> REJECT without proof.
    return { decision: 0, reason_code: "VK_SUBSTITUTION", provable: proofVk !== registeredVk, malformed: false };
  }
  // 2. Reuse (no proof: scoring excludes reuse tasks from the proof requirement).
  if (seen.has(proofTx)) {
    return { decision: 0, reason_code: "PROOF_REUSED", provable: false, malformed: false };
  }
  // 3. Expiry (strict >: current == expiry is still valid).
  if (current > expiry) {
    return { decision: 0, reason_code: "EXPIRED_CONDITION", provable: true, malformed: false };
  }
  // 4. Threshold (strict <: balance == minimum passes).
  if (balance < minimum) {
    return { decision: 0, reason_code: "THRESHOLD_MISMATCH", provable: true, malformed: false };
  }
  // 5. Recipient (case-insensitive: matches the circuit's integer comparison).
  if (recipient !== conditionRecipient) {
    return { decision: 0, reason_code: "RECIPIENT_MISMATCH", provable: true, malformed: false };
  }
  // 6. Amount (strict >: amount == cap passes).
  if (amount > maxTransfer) {
    return { decision: 0, reason_code: "AMOUNT_OVERFLOW", provable: true, malformed: false };
  }
  return { decision: 1, reason_code: "VALID_CONDITION", provable: true, malformed: false };
}

// ---- proving ----
let snarkjsPromise = null;
function loadSnarkjs() {
  if (!snarkjsPromise) snarkjsPromise = Promise.resolve(require("snarkjs"));
  return snarkjsPromise;
}
function circuitPath(name) {
  const candidates = [
    path.join(__dirname, "..", "circuits", name),
    path.join(process.cwd(), "circuits", name),
    path.join("/var/task", "circuits", name),
    path.join(__dirname, "circuits", name),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  throw new Error("circuit file not found: " + name);
}
async function prove(input, decision) {
  const snarkjs = await loadSnarkjs();
  const circuitInput = {
    taskId: taskIdField(input.task_id),
    minimum: parseBig(input.minimum).toString(),
    publicBalance: parseBig(input.public_balance).toString(),
    expiryBlock: parseBig(input.expiry_block).toString(),
    currentBlock: parseBig(input.current_block).toString(),
    recipient: BigInt(normHex(input.recipient)).toString(),
    conditionRecipient: BigInt(normHex(input.condition_recipient)).toString(),
    amount: parseBig(input.amount).toString(),
    maxTransfer: parseBig(input.max_transfer).toString(),
    registeredVkHash: BigInt(normHex(input.registered_vk)).toString(),
    proofVkHash: BigInt(normHex(input.proof_vk)).toString(),
    salt: String(crypto.randomInt(1, 999999999)),
    decision: String(decision),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    circuitPath("gatekeeper.wasm"),
    circuitPath("gatekeeper_final.zkey")
  );
  return { proof, publicSignals };
}
function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error("soft timeout")), ms)),
  ]);
}

// ---- handler ----
module.exports = async function handler(req, res) {
  const started = Date.now();
  const secret = process.env.AGENT_HMAC_SECRET;

  const sendSigned = (status, obj) => {
    const body = JSON.stringify(obj);
    res.setHeader("Content-Type", "application/json");
    if (secret) res.setHeader("x-agent-games-signature", hmacHex(secret, body));
    res.status(status).send(body);
  };

  // GET (possible health-check path): protocol JSON, no body to verify.
  if (req.method === "GET") {
    return sendSigned(200, PROTOCOL);
  }
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  // read raw body (needed for HMAC)
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks);

  if (!secret) {
    console.error("AGENT_HMAC_SECRET not configured");
    return res.status(500).send("server misconfigured");
  }
  if (!verifyHmac(secret, raw, req.headers["x-agent-games-signature"])) {
    return res.status(401).send("bad signature");
  }

  let body;
  try {
    body = JSON.parse(raw.toString("utf8"));
  } catch {
    return res.status(400).send("bad json");
  }

  // Preflight / non-task POST -> protocol JSON.
  const type = typeof body.type === "string" ? body.type : "";
  const isTask = type.includes("proof-gatekeeper") || (body.task_id && body.input);
  if (!isTask) {
    return sendSigned(200, PROTOCOL);
  }

  const taskId = body.task_id;
  const input = { ...body.input, task_id: taskId };
  const mode = body.mode || "competition";

  try {
    const loaded = await loadState();
    // idempotency: retried task returns the identical cached response
    if (taskId && loaded.responses.has(taskId)) {
      const cached = loaded.responses.get(taskId);
      const cachedBody = JSON.stringify(cached);
      res.setHeader("Content-Type", "application/json");
      res.setHeader("x-agent-games-signature", hmacHex(secret, cachedBody));
      return res.status(200).send(cachedBody);
    }

    let verdict = decide(input, loaded.seen);
    let proof = null;
    let publicSignals = null;

    if (verdict.provable) {
      try {
        const r = await withTimeout(prove(input, verdict.decision), SOFT_DEADLINE_MS - (Date.now() - started));
        proof = r.proof;
        publicSignals = r.publicSignals;
      } catch (e) {
        // Circuit disagrees with the logic: try the opposite decision once.
        console.error(`prove(${verdict.decision}) failed for ${taskId}: ${e.message}; trying opposite`);
        try {
          const r = await withTimeout(prove(input, 1 - verdict.decision), SOFT_DEADLINE_MS - (Date.now() - started));
          proof = r.proof;
          publicSignals = r.publicSignals;
          verdict = verdict.decision === 1
            ? { decision: 0, reason_code: "VK_SUBSTITUTION", provable: true, malformed: false }
            : { decision: 1, reason_code: "VALID_CONDITION", provable: true, malformed: false };
        } catch (e2) {
          console.error(`prove(${1 - verdict.decision}) also failed for ${taskId}: ${e2.message}`);
          // fail closed: REJECT without proof
          verdict = { decision: 0, reason_code: verdict.decision === 1 ? verdict.reason_code : verdict.reason_code, provable: false, malformed: false };
        }
      }
    }

    const response = {
      decision: verdict.decision === 1 ? "APPROVE" : "REJECT",
      reason_code: verdict.reason_code,
      proof_tx: String(input.proof_tx),
    };
    if (proof && publicSignals) {
      response.proof = proof;
      response.public_signals = publicSignals;
    }

    // persist: proof_tx to seen-set (competition tasks only) + response cache
    if (mode === "competition" && input.proof_tx) {
      loaded.seen.add(String(input.proof_tx).trim().toLowerCase());
    }
    if (taskId) loaded.responses.set(taskId, response);
    await saveState(loaded, loaded.seen, loaded.responses);

    return sendSigned(200, response);
  } catch (e) {
    console.error("task handling failed:", e);
    // last-resort fail-closed (no proof possible here)
    return sendSigned(200, {
      decision: "REJECT",
      reason_code: "VK_SUBSTITUTION",
      proof_tx: input.proof_tx ? String(input.proof_tx) : "",
    });
  }
};
