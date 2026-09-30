-- gcm.lua — AES-256-GCM (no AAD) producing the exact "v1:" blob the Worker,
-- WebCrypto and the Android app all speak: base64std(IV12 ‖ CT ‖ TAG16).
--
-- Why we don't use crypto.cipher_encrypt("AES-256-GCM",...): the LuatOS mbedtls
-- binding feeds a hard-coded AAD ("1234567890123456") into every GCM tag and
-- older firmware ignored the IV, so its tag is NOT WebCrypto-compatible. We
-- therefore build GCM by hand on top of the one primitive that is trustworthy
-- and universally present: AES-256-ECB. Keystream = ECB over CTR blocks;
-- H = ECB(0^16); EJ0 = ECB(J0); TAG = GHASH_H(pad16(CT) ‖ len64(0) ‖ len64(bitCT)) ⊕ EJ0.
--
-- Portability: GHASH runs on four 32-bit words via string.unpack(">I4I4I4I4").
-- It must be correct on BOTH 64-bit and 32-bit lua_Integer builds. On 32-bit,
-- ">I4" unpack yields negative ints for words ≥ 0x80000000 and hex literals
-- ≥ 0x80000000 wrap negative — but every op here is bitwise (shifts are logical,
-- xor/and/or are bit-pattern), we never compare words numerically, and packing
-- with ">I4" is size==sizeof(lua_Integer) on 32-bit so its overflow check is
-- skipped. On 64-bit we keep every word masked to 32 bits so ">I4" packs cleanly.
--
-- Dependencies: crypto.cipher_encrypt("AES-256-ECB","NONE",...), crypto.trng,
-- and the string extensions string.toBase64 / string.fromBase64. Nothing else.

local M = {}

local crypto = crypto
local unpack4 = string.unpack
local pack = string.pack
local schar = string.char
local sbyte = string.byte
local srep = string.rep

local MASK = 0xFFFFFFFF          -- on 32-bit this literal is -1 (all bits set); x & -1 == x
local ZERO16 = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

local function ecb(key32, block)
  -- One ECB call; block length is always a multiple of 16.
  return crypto.cipher_encrypt("AES-256-ECB", "NONE", block, key32)
end

-- GF(2^128) multiply in the GCM bit order (bit 0 = MSB of byte 0).
-- ponytail: bit-serial, 128 iterations per block. Upgrade path = precomputed
-- 4-bit table of H (16 entries) for ~8x fewer inner steps; not worth it until
-- the device is CPU-bound on large messages.
local function gf_mul(x1, x2, x3, x4, h1, h2, h3, h4)
  local z1, z2, z3, z4 = 0, 0, 0, 0
  local v1, v2, v3, v4 = x1, x2, x3, x4
  for i = 0, 127 do
    local bit
    if i < 32 then bit = (h1 >> (31 - i)) & 1
    elseif i < 64 then bit = (h2 >> (63 - i)) & 1
    elseif i < 96 then bit = (h3 >> (95 - i)) & 1
    else bit = (h4 >> (127 - i)) & 1 end
    if bit == 1 then
      z1 = z1 ~ v1; z2 = z2 ~ v2; z3 = z3 ~ v3; z4 = z4 ~ v4
    end
    local lsb = v4 & 1
    v4 = ((v4 >> 1) | ((v3 & 1) << 31)) & MASK
    v3 = ((v3 >> 1) | ((v2 & 1) << 31)) & MASK
    v2 = ((v2 >> 1) | ((v1 & 1) << 31)) & MASK
    v1 = (v1 >> 1) & MASK
    if lsb == 1 then v1 = v1 ~ 0xE1000000 end   -- R = 0xE1 ‖ 0^120
  end
  return z1, z2, z3, z4
end

-- GHASH over data (length must already be a multiple of 16), returns 16 bytes.
local function ghash(h1, h2, h3, h4, data)
  local y1, y2, y3, y4 = 0, 0, 0, 0
  for off = 1, #data, 16 do
    local x1, x2, x3, x4 = unpack4(">I4I4I4I4", data, off)
    y1, y2, y3, y4 = gf_mul(y1 ~ x1, y2 ~ x2, y3 ~ x3, y4 ~ x4, h1, h2, h3, h4)
  end
  return pack(">I4I4I4I4", y1, y2, y3, y4)
end

local function xor16(a, b)
  local a1, a2, a3, a4 = unpack4(">I4I4I4I4", a)
  local b1, b2, b3, b4 = unpack4(">I4I4I4I4", b)
  return pack(">I4I4I4I4", a1 ~ b1, a2 ~ b2, a3 ~ b3, a4 ~ b4)
end

-- XOR data (arbitrary length) with keystream ks (ks must be at least #data).
local function xor_stream(data, ks)
  local n = #data
  local out = {}
  local oi = 0
  local i = 1
  while i + 3 <= n do
    local a = unpack4(">I4", data, i)
    local b = unpack4(">I4", ks, i)
    oi = oi + 1
    out[oi] = pack(">I4", (a ~ b) & MASK)
    i = i + 4
  end
  while i <= n do
    oi = oi + 1
    out[oi] = schar((sbyte(data, i) ~ sbyte(ks, i)) & 0xFF)
    i = i + 1
  end
  return table.concat(out)
end

-- Keystream for `nbytes` of message: ECB over counter blocks iv‖uint32BE(n),
-- n = 2,3,...  (J0 = iv‖1 is reserved for EJ0, GCM starts the CTR at 2.)
-- ONE crypto.cipher_encrypt call over all concatenated counter blocks.
local function keystream(key32, iv, nbytes)
  local nblocks = (nbytes + 15) // 16
  if nblocks == 0 then return "" end
  local blk = {}
  for n = 2, nblocks + 1 do
    blk[n - 1] = iv .. pack(">I4", n)
  end
  return ecb(key32, table.concat(blk))
end

-- TAG over ciphertext ct (any length): GHASH_H(pad16(ct) ‖ 0^64 ‖ len64(bits ct)) ⊕ EJ0.
local function gcm_tag(key32, iv, ct)
  local h1, h2, h3, h4 = unpack4(">I4I4I4I4", ecb(key32, ZERO16))
  local ej0 = ecb(key32, iv .. "\0\0\0\1")
  local pad = (16 - #ct % 16) % 16
  local lenbits = #ct * 8
  -- length block: uint64BE(aad bits = 0) ‖ uint64BE(ct bits)
  local lenblk = pack(">I4I4I4I4", 0, 0, (lenbits >> 32) & MASK, lenbits & MASK)
  local gin = ct .. srep("\0", pad) .. lenblk
  return xor16(ghash(h1, h2, h3, h4, gin), ej0)
end

-- Constant-time-ish 16-byte compare: accumulate differences, never early-exit.
local function tags_equal(a, b)
  if #a ~= 16 or #b ~= 16 then return false end
  local diff = 0
  for i = 1, 16 do
    diff = diff | (sbyte(a, i) ~ sbyte(b, i))
  end
  return diff == 0
end

-- seal(key32, plaintext, iv12?) -> "v1:base64(iv‖ct‖tag)"
function M.seal(key32, plaintext, iv12)
  local iv = iv12 or crypto.trng(12)
  local ct = xor_stream(plaintext, keystream(key32, iv, #plaintext))
  local tag = gcm_tag(key32, iv, ct)
  return "v1:" .. string.toBase64(iv .. ct .. tag)
end

-- open(key32, v1str) -> plaintext or nil. Validates prefix, base64, length,
-- and verifies the tag BEFORE returning the plaintext. nil on any failure.
function M.open(key32, v1str)
  if type(v1str) ~= "string" then return nil end
  if v1str:sub(1, 3) ~= "v1:" then return nil end
  local blob = string.fromBase64(v1str:sub(4))
  if not blob or #blob < 28 then return nil end   -- 12 iv + 0 ct + 16 tag minimum
  local iv = blob:sub(1, 12)
  local ct = blob:sub(13, #blob - 16)
  local tag = blob:sub(#blob - 15)
  if not tags_equal(tag, gcm_tag(key32, iv, ct)) then return nil end
  return xor_stream(ct, keystream(key32, iv, #ct))
end

-- Boot self-test against fixed known-answer vectors (K=0^32, IV=0^12).
-- Expected bytes embedded raw so selftest needs no hex helper.
function M.selftest()
  local k = srep("\0", 32)
  local iv = srep("\0", 12)

  -- empty plaintext -> tag 530f8afbc74536b9a963b4f1c4cb738b
  local s0 = M.seal(k, "", iv)
  if s0 ~= "v1:" .. string.toBase64(iv .. "\x53\x0f\x8a\xfb\xc7\x45\x36\xb9\xa9\x63\xb4\xf1\xc4\xcb\x73\x8b") then
    return false
  end
  if M.open(k, s0) ~= "" then return false end

  -- 16 zero bytes -> ct cea7403d4d606b6e074ec5d3baf39d18, tag d0d1c8a799996bf0265b98b5d48ab919
  local pt = srep("\0", 16)
  local s1 = M.seal(k, pt, iv)
  local expect = iv
    .. "\xce\xa7\x40\x3d\x4d\x60\x6b\x6e\x07\x4e\xc5\xd3\xba\xf3\x9d\x18"
    .. "\xd0\xd1\xc8\xa7\x99\x99\x6b\xf0\x26\x5b\x98\xb5\xd4\x8a\xb9\x19"
  if s1 ~= "v1:" .. string.toBase64(expect) then return false end
  if M.open(k, s1) ~= pt then return false end

  return true
end

return M
