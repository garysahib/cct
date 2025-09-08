package cct

# allow_tool_call returns true if a given input (tool call + runtime signals + cct) is permitted
allow_tool_call {
  valid_cct
  tool_allowed
  not risk_blocked
}

# Basic CCT sanity & time checks
valid_cct {
  input.cct.typ == "CCT"
  input.cct.iss == "https://aag.yourco.com"
  now := time.now_ns() / 1000000000
  now < input.cct.exp
  input.cct.jti != ""
}

# Tool is present in capabilities and scope matches requested segment
tool_allowed {
  some i
  cap := input.cct.cap[i]
  cap.tool == input.tool.name
  scope_ok(cap.scope, input.request.scope)
  # optional: check attr constraints
  allowed_limits(cap.limit, input.request)
}

# Scope matching helper (very simple namespace match)
scope_ok(cap_scope, req_scope) {
  startswith(req_scope, cap_scope)
}

allowed_limits(limit, request) {
  # if no limit, allow
  limit == null
  # or enforce numeric limits
  # example: rows
  or (
    limit.rows == null
  )
  or (
    limit.rows != null
    request.rows <= limit.rows
  )
}

# Risk-based blocking (example)
risk_blocked {
  input.signals.risk_score >= 80
}

# Attenuation: create child CCT with reduced caps (example)
# This is an outline: actual minting occurs in AAG
attenuate_cap(cap, narrowed_scope, narrower_limit) = newcap {
  newcap := {
    "tool": cap.tool,
    "scope": narrowed_scope,
    "limit": narrower_limit
  }
}
