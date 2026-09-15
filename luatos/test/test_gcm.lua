-- test_gcm.lua — run from repo root: `cd /Users/sidym/Workspace/sms && lua luatos/test/test_gcm.lua`
-- Groups: (A) vectors.json KATs, (B) critic G10 fixture, (C) 20 random round
-- trips cross-checked against Node, (D) tamper rejection, (E) selftest.

package.path = "luatos/?.lua;luatos/test/?.lua;" .. package.path
require("fake_crypto")
local gcm = require("gcm")

local VECTORS = os.getenv("GCM_VECTORS")
  or "/private/tmp/claude-501/-Users-sidym-Workspace-abc/5f75b85b-8ab7-41fe-9c46-af86ca13d16f/scratchpad/gcm/vectors.json"
local SCRATCH = os.getenv("GCM_SCRATCH")
  or "/private/tmp/claude-501/-Users-sidym-Workspace-abc/5f75b85b-8ab7-41fe-9c46-af86ca13d16f/scratchpad/gcm/tmp"

local fails = 0
local function group(name, ok, detail)
  print((ok and "PASS  " or "FAIL  ") .. name .. (detail and ("  -- " .. detail) or ""))
  if not ok then fails = fails + 1 end
end

local function fromhex(h) return string.fromHex(h) end
local function tohex(s) return (select(1, string.toHex(s))):lower() end

local function run(cmd)
  local f = assert(io.popen(cmd, "r"))
  local out = f:read("*a")
  f:close()
  return out
end

local function write_file(path, data)
  local f = assert(io.open(path, "wb")); f:write(data); f:close()
end

local function split_lines(s)
  local t = {}
  for line in (s .. "\n"):gmatch("(.-)\n") do t[#t + 1] = line end
  while #t > 0 and t[#t] == "" do t[#t] = nil end
  return t
end

-- ---- (A) vectors.json -----------------------------------------------------
do
  local dump = run("node -e 'const v=require(process.argv[1]);"
    .. "let o=v.key_hex+\"\\n\";for(const c of v.cases)o+=c.iv+\"\\t\"+c.pt_hex+\"\\t\"+c.v1+\"\\n\";"
    .. "process.stdout.write(o)' '" .. VECTORS .. "'")
  local lines = split_lines(dump)
  local key = fromhex(lines[1])
  local ok, ncases, why = true, 0, nil
  for i = 2, #lines do
    local iv_hex, pt_hex, v1 = lines[i]:match("^(%x*)\t(%x*)\t(.+)$")
    if not iv_hex then ok = false; why = "bad dump line " .. i; break end
    ncases = ncases + 1
    local iv, pt = fromhex(iv_hex), fromhex(pt_hex)
    local got = gcm.seal(key, pt, iv)
    if got ~= v1 then ok = false; why = "case " .. (i - 1) .. " seal mismatch"; break end
    if gcm.open(key, v1) ~= pt then ok = false; why = "case " .. (i - 1) .. " open mismatch"; break end
  end
  group("A vectors.json (" .. ncases .. " KATs seal+open)", ok, why)
end

-- ---- (B) critic G10 fixture ----------------------------------------------
do
  local key = fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
  local iv = fromhex("000102030405060708090a0b")
  local pt = '{"s":"10086","b":"测试","k":"SIM 1 · 中国移动","d":"0123456789abcdef"}'
  local expect = "v1:AAECAwQFBgcICQoLbTrGFHpr/Ib5A1neHfcGDVQXQctw7NQKGw5jpwbYCGSriZVbwi1mB37uS2R3BkFkpOg/pL7K+FcHFYTHhKWrz4NDUkja0ra50Qn4slJGK0569GuuejKho1me3nn+"
  local got = gcm.seal(key, pt, iv)
  local ok = (got == expect) and (gcm.open(key, expect) == pt)
  group("B critic G10 fixture (seal exact + open)", ok, (not ok) and ("got " .. got) or nil)
end

-- ---- (C) 20 random round trips vs Node -----------------------------------
do
  math.randomseed(0x5eed)
  local N = 20
  local cases = {}
  local tsv = {}
  for i = 1, N do
    local key = crypto.trng(32)
    local iv = crypto.trng(12)
    local len = math.random(0, 3100)
    local pt = len > 0 and crypto.trng(len) or ""
    local v1lua = gcm.seal(key, pt, iv)
    cases[i] = { key = key, pt = pt, v1 = v1lua }
    tsv[i] = tohex(key) .. "\t" .. tohex(iv) .. "\t" .. tohex(pt) .. "\t" .. v1lua
  end
  local tsvpath = SCRATCH .. "/xcheck_cases.tsv"
  local jspath = SCRATCH .. "/xcheck.js"
  write_file(tsvpath, table.concat(tsv, "\n") .. "\n")
  write_file(jspath, [[
const fs=require("fs"),crypto=require("crypto");
const lines=fs.readFileSync(process.argv[2],"utf8").split("\n").filter(Boolean);
let out="";
for(let i=0;i<lines.length;i++){
  const p=lines[i].split("\t");
  const key=Buffer.from(p[0],"hex"),iv=Buffer.from(p[1],"hex"),pt=Buffer.from(p[2],"hex"),v1lua=p[3];
  const c=crypto.createCipheriv("aes-256-gcm",key,iv);
  const ct=Buffer.concat([c.update(pt),c.final()]);const tag=c.getAuthTag();
  const v1node="v1:"+Buffer.concat([iv,ct,tag]).toString("base64");
  let dec=0;
  try{
    const raw=Buffer.from(v1lua.slice(3),"base64");
    const div=raw.subarray(0,12),dtag=raw.subarray(raw.length-16),dct=raw.subarray(12,raw.length-16);
    const d=crypto.createDecipheriv("aes-256-gcm",key,div);d.setAuthTag(dtag);
    const pp=Buffer.concat([d.update(dct),d.final()]);
    dec=Buffer.compare(pp,pt)===0?1:0;
  }catch(e){dec=0;}
  out+=i+"\t"+((v1node===v1lua)?1:0)+"\t"+dec+"\t"+v1node+"\n";
}
process.stdout.write(out);
]])
  local res = split_lines(run("node '" .. jspath .. "' '" .. tsvpath .. "'"))
  local ok, why = true, nil
  if #res ~= N then ok = false; why = "expected " .. N .. " node lines, got " .. #res end
  for _, line in ipairs(res) do
    local idx, seal, dec, v1node = line:match("^(%d+)\t(%d)\t(%d)\t(.+)$")
    if not idx then ok = false; why = "bad node line"; break end
    idx = tonumber(idx) + 1
    if seal ~= "1" then ok = false; why = "case " .. idx .. " Lua-seal != Node-seal"; break end
    if dec ~= "1" then ok = false; why = "case " .. idx .. " Node could not decrypt Lua v1"; break end
    -- Node-seal -> Lua-open
    if gcm.open(cases[idx].key, v1node) ~= cases[idx].pt then
      ok = false; why = "case " .. idx .. " Lua-open of Node v1 mismatch"; break
    end
  end
  group("C 20 random round trips vs Node (both directions)", ok, why)
end

-- ---- (D) tamper rejection -------------------------------------------------
do
  local key = fromhex("0f0e0d0c0b0a09080706050403020100" .. "1f1e1d1c1b1a19181716151413121110")
  local iv = fromhex("aabbccddeeff001122334455")
  local pt = "tamper me: the quick brown fox jumps over the lazy dog"
  local good = gcm.seal(key, pt, iv)
  assert(gcm.open(key, good) == pt, "sanity: good blob must open")
  local blob = string.fromBase64(good:sub(4))
  local function flip(s, pos)
    local b = s:byte(pos)
    return s:sub(1, pos - 1) .. string.char(b ~ 0xFF) .. s:sub(pos + 1)
  end
  local function reblob(b) return "v1:" .. string.toBase64(b) end

  local ct_flip = reblob(flip(blob, 13))                 -- first CT byte
  local tag_flip = reblob(flip(blob, #blob))             -- last TAG byte
  local truncated = reblob(blob:sub(1, 20))              -- < 28 bytes
  local trunc_ct = reblob(blob:sub(1, #blob - 1))        -- ≥28 but tag short/shifted
  local wrong_key = fromhex("00000000000000000000000000000000" .. "00000000000000000000000000000001")
  local wrong_prefix = "v2:" .. good:sub(4)

  local ok = gcm.open(key, ct_flip) == nil
    and gcm.open(key, tag_flip) == nil
    and gcm.open(key, truncated) == nil
    and gcm.open(key, trunc_ct) == nil
    and gcm.open(wrong_key, good) == nil
    and gcm.open(key, wrong_prefix) == nil
  group("D tamper rejection (ct/tag/truncate/wrong-key/wrong-prefix -> nil)", ok)
end

-- ---- (E) selftest ---------------------------------------------------------
group("E gcm.selftest()", gcm.selftest() == true)

print(string.rep("-", 40))
if fails == 0 then
  print("ALL GROUPS PASS")
  os.exit(0)
else
  print(fails .. " GROUP(S) FAILED")
  os.exit(1)
end
