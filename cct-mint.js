// high-level steps
// 1. Authenticate OIDC token at AAG
// 2. Evaluate requested plan (tools, segments) and risk signals
// 3. Run Rego policy to authorize
// 4. Mint CCT (JWS) with PoP binding (DPoP key thumbprint or bind to mTLS cert SPKI)
// 5. Return CCT to orchestrator/agent

function mintCCT(request) {
  oidcCtx = validateOIDCToken(request.oidc_token)
  plan = request.plan  // {tools, scope, prompt_sha256, model}
  signals = collectSignals(request)
  input = { cct: {}, request: plan, signals: signals }
  # call OPA/rego -> decision
  decision = opa.evaluate("cct.allow_mint", input)
  if (!decision.allow) throw Error("not allowed")
  cct = {
    typ: "CCT",
    iss: "https://aag.yourco.com",
    sub: `agent:${plan.agent}@${oidcCtx.tenant}`,
    act: `user:${oidcCtx.sub}`,
    aud: plan.aud,
    cap: plan.capabilities,
    ctx: plan.ctx,
    proof: { type: "dpop", jkt: request.dpop_jkt },
    iat: now(),
    exp: now() + 60 // short TTL
  }
  signed = signJWS(cct, AAG_PRIVATE_KEY)
  return signed
}
