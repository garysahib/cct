# cct
Capabilities and Context (Conditions) Tokens

Love this direction. Here’s a crisp, practitioner-oriented unpacking of each point with concrete patterns you can implement right away (and a straw-man spec you can iterate on).

⸻

1) Marry OIDC/OAuth with AI-centric protocols

Idea: keep your enterprise identity source of truth (OIDC/OAuth) but never let raw human/ service bearer tokens leak into agent runtimes. Use them only to mint short-lived, AI-native capability artifacts tailored to prompts, tools, and data slices.

Pattern
	•	Authenticate principals (humans/services) with OIDC/OAuth as usual → get ID token / access token at the gateway, not inside the agent.
	•	Token exchange at an Agent Access Gateway (AAG):
	•	Input: OIDC context (subject, tenant, device posture), risk signals.
	•	Output: CCT (Capabilities & Context Token): an attenuated, AI-shaped token that encodes what this agent may do + under what context.
	•	Bind CCT to:
	•	model identity + version,
	•	tool list / API set,
	•	dataset segments,
	•	purpose-of-use,
	•	prompt hash (or content digest),
	•	audience (specific service) + channel (MCP, gRPC, HTTP),
	•	proof-of-possession (DPoP or mTLS), and
	•	expiry in seconds, not minutes.

This keeps OIDC/OAuth for who, while CCT governs what, with which data, for what prompt, and where.

⸻

2) Don’t hand contemporary tokens to agents—introduce CCTs

Why: Bearer access tokens are too broad and replayable; agents chain calls, self-reflect, and route—risk explodes.

CCT design sketch (capability-based)
	•	Format: detached JWS/JWT or CWT, or a capability system like Biscuit/Macaroons (attenuation-friendly).
	•	Key claims (examples)
 {
  "typ": "CCT",
  "iss": "aag.yourco.com",
  "sub": "agent:orders-summarizer@tenant-123",
  "act": "on-behalf-of:user:alice",             // delegated subject
  "aud": ["svc:orders-api.v2", "svc:vector-db"],
  "cap": [
    {"tool":"orders.read","scope":"tenant-123:region-us:pii-redacted","limit":{"row_count":5000}},
    {"tool":"vector.search","scope":"kb:shipping","topK":10}
  ],
  "ctx": {
    "model": "gpt-xyz:2025-08",
    "prompt_sha256": "…",
    "purpose": "customer_support_summary",
    "chain_id": "req-7f2…",
    "caller_chain": ["ui:web", "svc:orchestrator", "agent:router"]
  },
  "proof": { "dpop_jkt": "…", "mtls_spki": "…" },
  "exp": 169,  // seconds to live
  "nbf": 0
}

{
  "typ": "CCT",
  "iss": "aag.yourco.com",
  "sub": "agent:orders-summarizer@tenant-123",
  "act": "on-behalf-of:user:alice",             // delegated subject
  "aud": ["svc:orders-api.v2", "svc:vector-db"],
  "cap": [
    {"tool":"orders.read","scope":"tenant-123:region-us:pii-redacted","limit":{"row_count":5000}},
    {"tool":"vector.search","scope":"kb:shipping","topK":10}
  ],
  "ctx": {
    "model": "gpt-xyz:2025-08",
    "prompt_sha256": "…",
    "purpose": "customer_support_summary",
    "chain_id": "req-7f2…",
    "caller_chain": ["ui:web", "svc:orchestrator", "agent:router"]
  },
  "proof": { "dpop_jkt": "…", "mtls_spki": "…" },
  "exp": 169,  // seconds to live
  "nbf": 0
}

package cct.authz

default allow = false

allow {
  input.cct.cap[_].tool == input.tool
  dataset := input.cct.cap[_].scope
  dataset == sprintf("tenant-%s:region-%s:%s", [input.tenant, input.region, input.label])
  input.ctx.model == input.cct.ctx.model
  input.ctx.prompt_sha256 == input.cct.ctx.prompt_sha256
  time.now_ns() < input.cct.exp * 1e9
  input.risk.score < 70
}


⸻

4) Data: segment, label, and bind to capabilities

Why: Agents are generalists; your data must not be. Capabilities are only as safe as your segments.

Do now
	•	Uniform data labeling: tenant, geography, sensitivity (public/internal/confidential/regulated), PII categories, retention, lineage.
	•	Physical & logical segmentation: per-tenant schemas or databases; separate embeddings for each segment; encryption domains aligned to segments.
	•	Policy-aware retrieval: Tool adapters must pass the requested segment and user intent; vector search must filter by segment labels before scoring.
	•	Redaction/transformers: On “border” reads (PII, secrets), run masking or structured redaction; expose only what the capability allows (e.g., last-4, aggregates).
	•	Audit everything: link CCT chain_id to data access logs for full provenance.

⸻

5) A verification layer between every prompt and task

Goal: treat agent execution like an inference pipeline with gates. Nothing runs “raw.”

Reference pipeline (analogy to KServe)
	1.	Input Gate
	•	Validate prompt size, MIME types, embedded links.
	•	Compute prompt_sha256, detect jailbreak patterns, classify intent/purpose.
	2.	Planning/Reasoning Gate
	•	The agent proposes a plan (tools, data segments, estimated outputs).
	•	Plan Validator checks plan against CCT capabilities and policies (OPA).
	•	Optionally require human-in-the-loop for risky intents.
	3.	Execution Gate (per tool call)
	•	Inline authZ: CCT + signals → decision.
	•	Data transformers: redact/mask/aggregate as required.
	•	Rate/volume governors.
	4.	Explainer/Verifier Gate
	•	Validate outputs vs. allowed data (no leakage), check factual grounding (cite-required segments), run toxicity/PII leakage detectors.
	•	Optionally run a secondary model or symbolic checks (regex/validators/unit rules) on outputs.
	5.	Output Gate
	•	Attach Decision Record (what was allowed/denied, caps used).
	•	Store provenance: {chain_id, cct_id, plan, approvals, data segments, hashes}.
	•	Emit shared signals for risk engines & SIEM.

⸻

Putting it together: end-to-end flow (Agent↔Agent over MCP)
	1.	User → Orchestrator authenticates via OIDC.
	2.	Orchestrator → AAG: exchanges OIDC for a CCT tailored to the prompt, model, tools, and segments.
	3.	Agent A (Router) receives the CCT (PoP-bound) and creates a plan.
	4.	Verification Layer validates plan ↔ CCT.
	5.	Agent A → Agent B (Tool Specialist) over MCP sends a narrowed child-CCT (attenuated scopes, shorter TTL).
	6.	Each tool call by Agent B performs inline authZ using its CCT + live signals, applies redaction/filters tied to the segment labels.
	7.	Explainer/Verifier checks outputs; Output Gate emits audit + shared signals.

⸻

Implementation notes (fast path)
	•	AAG / Token Service: build as a sidecar or edge service; support JWT (for ease) and Biscuit (for attenuation). Enable DPoP or mTLS so CCTs are proof-of-possession, not pure bearer.
	•	OPA everywhere: embed lightweight OPA in tool adapters or centralize via Envoy/ext_authz.
	•	Hash & bind: always bind CCT to model, prompt_sha256, aud, and chain_id. If any changes, force a new CCT.
	•	Segmentation-first embeddings: separate vector indexes per tenant/sensitivity; never “filter-after-search”—filter-before-search.
	•	Shared signals bus: publish cct.issued, cct.denied, cct.revoked, agent.plan_flagged, data.accessed to your risk engine and SIEM.
	•	Short TTLs + revocation: TTL in tens of seconds; allow push revocation by chain_id.

⸻

Threats this closes
	•	Token exfiltration: no OAuth tokens in agent memory; CCTs are PoP-bound and short-lived.
	•	Over-broad access: capabilities encode exact tools/data; attenuation controls fan-out.
	•	Prompt pivot / tool injection: prompt hash + plan validation blocks capability misuse.
	•	Data leakage: segment-aware retrieval + output verification + DLP.
	•	Confused deputy between agents: child-CCTs can’t broaden authority; audience binding prevents cross-service replay.

⸻

Minimal MVP checklist
	•	Build AAG: OIDC → CCT minting, PoP, 30–120s TTL
	•	Define cap and ctx schema; support attenuation
	•	Add Input/Plan/Execution/Output gates around your MCP runtime
	•	Embed OPA checks in every tool adapter
	•	Label & segment your top 3 data sources; wire redaction
	•	Stand up a signals topic (cct.*, agent.*) and basic risk rules

