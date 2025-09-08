# pseudo python
def call_tool(tool_url, cct, tool_request):
    parsed = verify_jws(cct)  # verify signature + exp
    # run local rego check (embedded OPA) with runtime signals
    input = {"cct": parsed, "tool": tool_request, "signals": collect_runtime_signals()}
    allow = opa.evaluate("cct.allow_tool_call", input)
    if not allow:
        raise Forbidden("call blocked")
    # perform data redaction / filter according to parsed.cap
    tool_request = apply_redaction(parsed, tool_request)
    # attach PoP or mTLS
    resp = http_post(tool_url, tool_request, client_cert=get_agent_cert(parsed))
    return resp
