-- fake_crypto.lua — minimal LuatOS shims so gcm.lua runs under stock Lua 5.4.
-- Only defines what is missing, so it is harmless if some names already exist.
-- AES-256-ECB is delegated to the system `openssl`; everything else is pure Lua.

-- Scratch dir for the openssl temp files (keep binary I/O off stdin pipes).
local SCRATCH = os.getenv("GCM_SCRATCH")
  or "/private/tmp/claude-501/-Users-sidym-Workspace-abc/5f75b85b-8ab7-41fe-9c46-af86ca13d16f/scratchpad/gcm/tmp"
os.execute("mkdir -p '" .. SCRATCH .. "' 2>/dev/null")

local function read_file(path, mode)
  local f = io.open(path, mode or "rb")
  if not f then return nil end
  local d = f:read("*a")
  f:close()
  return d
end

local function write_file(path, data)
  local f = assert(io.open(path, "wb"))
  f:write(data)
  f:close()
end

local function to_hex_lower(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- ---- crypto ---------------------------------------------------------------
_G.crypto = _G.crypto or {}

if not crypto.cipher_encrypt then
  local seq = 0
  crypto.cipher_encrypt = function(typ, pad, str, key, _iv)
    assert(typ == "AES-256-ECB" and pad == "NONE",
      "fake_crypto only supports AES-256-ECB/NONE, got " .. tostring(typ) .. "/" .. tostring(pad))
    if #str == 0 then return "" end
    assert(#str % 16 == 0, "ECB input must be a multiple of 16 bytes")
    seq = seq + 1
    local infile = SCRATCH .. "/ecb_in_" .. seq
    local outfile = SCRATCH .. "/ecb_out_" .. seq
    write_file(infile, str)
    local cmd = string.format(
      "openssl enc -aes-256-ecb -nopad -K %s -in '%s' -out '%s' 2>/dev/null",
      to_hex_lower(key), infile, outfile)
    assert(os.execute(cmd), "openssl ECB failed")
    local out = read_file(outfile)
    os.remove(infile); os.remove(outfile)
    return out
  end
end

if not crypto.trng then
  crypto.trng = function(n)
    if n <= 0 then return "" end
    local f = assert(io.open("/dev/urandom", "rb"))
    local d = f:read(n)  -- exactly n bytes; never read("*a") on an infinite stream
    f:close()
    return d
  end
end

-- ---- base64 (standard alphabet, '=' padding) ------------------------------
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

if not string.toBase64 then
  string.toBase64 = function(data)
    local out, oi = {}, 0
    local n = #data
    local i = 1
    while i <= n do
      local b1 = data:byte(i)
      local b2 = data:byte(i + 1)
      local b3 = data:byte(i + 2)
      local c1 = b1 >> 2
      local c2 = ((b1 & 3) << 4) | ((b2 or 0) >> 4)
      oi = oi + 1; out[oi] = B64:sub(c1 + 1, c1 + 1)
      oi = oi + 1; out[oi] = B64:sub(c2 + 1, c2 + 1)
      if b2 then
        local c3 = ((b2 & 15) << 2) | ((b3 or 0) >> 6)
        oi = oi + 1; out[oi] = B64:sub(c3 + 1, c3 + 1)
      else
        oi = oi + 1; out[oi] = "="
      end
      if b3 then
        local c4 = b3 & 63
        oi = oi + 1; out[oi] = B64:sub(c4 + 1, c4 + 1)
      else
        oi = oi + 1; out[oi] = "="
      end
      i = i + 3
    end
    return table.concat(out)
  end
end

if not string.fromBase64 then
  local D = {}
  for i = 1, #B64 do D[B64:byte(i)] = i - 1 end
  string.fromBase64 = function(str)
    if type(str) ~= "string" then return "" end
    -- collect alphabet symbols only; '=' and whitespace are dropped
    local vals, vi = {}, 0
    for i = 1, #str do
      local v = D[str:byte(i)]
      if v then vi = vi + 1; vals[vi] = v end
    end
    local out, oi = {}, 0
    local i = 1
    while i <= vi do
      local s1 = vals[i]
      local s2 = vals[i + 1]
      if not s2 then break end
      local s3 = vals[i + 2]
      local s4 = vals[i + 3]
      oi = oi + 1; out[oi] = string.char(((s1 << 2) | (s2 >> 4)) & 0xFF)
      if s3 then oi = oi + 1; out[oi] = string.char(((s2 << 4) | (s3 >> 2)) & 0xFF) end
      if s4 then oi = oi + 1; out[oi] = string.char(((s3 << 6) | s4) & 0xFF) end
      i = i + 4
    end
    return table.concat(out)
  end
end

-- ---- hex (LuatOS: toHex returns TWO values, UPPERCASE hex + length) --------
if not string.toHex then
  string.toHex = function(s)
    local h = s:gsub(".", function(c) return string.format("%02X", c:byte()) end)
    return h, #s
  end
end

if not string.fromHex then
  string.fromHex = function(h)
    return (h:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
  end
end

-- ---- log ------------------------------------------------------------------
_G.log = _G.log or {
  info = print, warn = print, error = print, debug = function() end,
}

return true
