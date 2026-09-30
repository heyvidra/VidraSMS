-- test_gw.lua — unit tests for gw.lua's pure helpers plus a scheduler smoke
-- test of the runtime under test/fake_luatos.lua. Run: lua luatos/test/test_gw.lua
-- Uses the real luatos/gcm.lua (same module the device runs). The runtime part
-- boots through the real main.lua (fake.config as config.lua, HTTP mocked) so
-- registration, trust gating and the web commands run the real _G.gw_cmd.

local here = debug.getinfo(1, "S").source:match("^@(.*)/[^/]*$") or "."
package.path = here .. "/?.lua;" .. here .. "/../?.lua;" .. package.path
local REPO = here .. "/.."

local fake = require("fake_luatos")
fake.quiet = true

PROJECT, VERSION = "smsgw", "1.0.0"
local gw = require("gw")
local gcm = require("gcm")

-- ---- tiny harness ------------------------------------------------------------
local pass, fail = 0, 0
local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function eq(name, got, want)
  if got == want then pass = pass + 1; print("ok   " .. name)
  else
    fail = fail + 1
    print("FAIL " .. name)
    print("     want: " .. (type(want) == "string" and ('"' .. want .. '" [' .. hex(want) .. "]") or tostring(want)))
    print("     got:  " .. (type(got) == "string" and ('"' .. got .. '" [' .. hex(got) .. "]") or tostring(got)))
  end
end
local function ok(name, cond) eq(name, cond and true or false, true) end
local function read_file(p) local f = io.open(p, "rb"); if not f then return nil end; local d = f:read("a"); f:close(); return d end
local function log_has(s) for _, l in ipairs(fake.log_lines) do if l:find(s, 1, true) then return true end end return false end

-- ---- json_escape --------------------------------------------------------------
print("== json_escape")
eq("quotes", gw.json_escape('a"b'), 'a\\"b')
eq("backslash", gw.json_escape('a\\b'), 'a\\\\b')
eq("newline/cr/tab", gw.json_escape("a\nb\rc\td"), 'a\\nb\\rc\\td')
eq("control -> \\u001f lowercase", gw.json_escape("x\31y"), 'x\\u001fy')
eq("control 0x01", gw.json_escape("\1"), '\\u0001')
eq("DEL passes through", gw.json_escape("\127"), "\127")
eq("raw UTF-8 passthrough", gw.json_escape("验证码 123456，5分钟内有效。"), "验证码 123456，5分钟内有效。")
eq("slash not escaped", gw.json_escape("a/b"), "a/b")
eq("nil -> empty", gw.json_escape(nil), "")

-- ---- clamp_body ---------------------------------------------------------------
print("== clamp_body")
eq("marker is 11 bytes", #gw.MARKER, 11)
eq("short body untouched", gw.clamp_body("hello", 100), "hello")
eq("exactly limit untouched", gw.clamp_body(string.rep("a", 20), 20), string.rep("a", 20))
-- limit 20 → room 9; "中" is 3 bytes: 9 bytes = 3 chars exactly on a boundary
eq("cut on boundary", gw.clamp_body(string.rep("中", 10), 20), "中中中" .. gw.MARKER)
-- limit 21 → room 10: 3 chars + 1 stray byte → walk back to 9
eq("cut mid-char walks back", gw.clamp_body(string.rep("中", 10), 21), "中中中" .. gw.MARKER)
-- limit 22 → room 11: 3 chars + 2 stray bytes → walk back to 9
eq("cut mid-char walks back 2", gw.clamp_body(string.rep("中", 10), 22), "中中中" .. gw.MARKER)
-- 4-byte char (emoji) cut after 1..3 bytes
eq("4-byte char cut", gw.clamp_body("ab" .. string.rep("😀", 5), 11 + 4), "ab" .. gw.MARKER)
eq("4-byte char kept", gw.clamp_body("ab" .. string.rep("😀", 5), 11 + 6), "ab😀" .. gw.MARKER)
eq("ascii cut", gw.clamp_body(string.rep("x", 50), 20), string.rep("x", 9) .. gw.MARKER)
eq("tiny limit -> marker only", gw.clamp_body(string.rep("x", 50), 5), gw.MARKER)

-- ---- build_inbound: G5 example, byte-exact -----------------------------------
print("== build_inbound")
eq("G5 fixture", gw.build_inbound("10086", "测试", "SIM 1 · 中国移动", "0123456789abcdef"),
  '{"s":"10086","b":"测试","k":"SIM 1 · 中国移动","d":"0123456789abcdef"}')
eq("no k, no d", gw.build_inbound("10086", "hi", nil, nil), '{"s":"10086","b":"hi"}')
eq("blank k omitted", gw.build_inbound("10086", "hi", "  ", "abcd"), '{"s":"10086","b":"hi","d":"abcd"}')
eq("escaping inside", gw.build_inbound('a"b', "l1\nl2", "SIM 1", "d"), '{"s":"a\\"b","b":"l1\\nl2","k":"SIM 1","d":"d"}')
eq("missed call shape", gw.build_inbound("+8613800138000", "未接来电", "SIM 1 · 中国电信", "0123456789abcdef"),
  '{"s":"+8613800138000","b":"未接来电","k":"SIM 1 · 中国电信","d":"0123456789abcdef"}')

-- Room math for a 5000-byte Chinese body, sender "10086", k "SIM 1 · 中国电信", d = 16 hex.
--   escaped sender = 5 bytes
--   k = "SIM 1 " (6) + "·" (2) + " " (1) + "中国电信" (12) = 21 bytes → +8 = 29
--   d = 16 bytes → +8 = 24
--   overhead = 24 + 29 + 24 = 77 ; room = 3000 - 5 - 77 = 2918
--   clamp: 2918 - 11 (marker) = 2907 bytes kept before the marker
-- Body = "A" .. "中文测试" × 416 .. "1234567" (1 + 4992 + 7 = 5000 bytes). The
-- first 2907 bytes are "A" + 2906 bytes of Chinese = 968 full chars (2904 B)
-- + 2 stray bytes → walk back → "A" + 968 chars (242 reps of the 4-char group).
do
  local k = "SIM 1 · 中国电信"
  eq("k label is 21 bytes", #k, 21)
  local body = "A" .. string.rep("中文测试", 416) .. "1234567"
  eq("body is 5000 bytes", #body, 5000)
  local want_b = "A" .. string.rep("中文测试", 242) .. gw.MARKER
  eq("clamped body bytes", #want_b, 1 + 2904 + 11)
  local want = '{"s":"10086","b":"' .. want_b .. '","k":"' .. k .. '","d":"0123456789abcdef"}'
  local got = gw.build_inbound("10086", body, k, "0123456789abcdef")
  eq("5000-byte body room math", got, want)
  -- JSON skeleton {"s":"10086","b":"","k":"<21>","d":"<16>"} = 71 bytes; Android's
  -- overhead constant (24 + k+8 + d+8 = 77) is 6 bytes conservative on purpose.
  eq("plaintext = 71 + clamped body", #got, 71 + #want_b)
  ok("plaintext ≤ 3000", #got <= 3000)
  -- Exactly-on-boundary variant: body of pure 3-byte chars, 2907 = 969 chars.
  local body2 = string.rep("中", 1700)
  local got2 = gw.build_inbound("10086", body2, k, "0123456789abcdef")
  eq("boundary body", got2, '{"s":"10086","b":"' .. string.rep("中", 969) .. gw.MARKER .. '","k":"' .. k .. '","d":"0123456789abcdef"}')
  eq("boundary plaintext = 71 + 2907 + 11", #got2, 2989)
  -- Escaping blow-up: 5000 quotes double when escaped; the shrink loop must converge ≤ room.
  local body3 = string.rep('"', 5000)
  local got3 = gw.build_inbound("10086", body3, k, "0123456789abcdef")
  ok("escaped body shrinks to fit", #got3 <= 3000)
  ok("escaped body still ends with marker", got3:find(gw.MARKER .. '","k"', 1, true) ~= nil)
  -- Minimum room of 64 when the sender is huge.
  local got4 = gw.build_inbound(string.rep("s", 3000), string.rep("b", 200), k, "0123456789abcdef")
  eq("min room 64 -> 53 body bytes + marker", got4:match('"b":"(.-)","k"'), string.rep("b", 53) .. gw.MARKER)
end

-- ---- format_body ---------------------------------------------------------------
print("== format_body")
eq("fresh message unchanged", gw.format_body("hi", 1700000000, 1700000000 + 119), "hi")
eq("old message gets UTC+8 prefix", gw.format_body("hi", 1700000000, 1700000000 + 120), "[原时间 11-15 06:13]\nhi")
eq("unsynced clock skipped", gw.format_body("hi", 12345, 12345 + 600), "hi")
eq("nil ts skipped", gw.format_body("hi", nil, 1700000000), "hi")

-- ---- carrier_from_imsi / sim_label ----------------------------------------------
print("== carrier_from_imsi")
for plmn, want in pairs({
  ["46000"] = "中国移动", ["46002"] = "中国移动", ["46004"] = "中国移动", ["46007"] = "中国移动", ["46008"] = "中国移动",
  ["46001"] = "中国联通", ["46006"] = "中国联通", ["46009"] = "中国联通",
  ["46003"] = "中国电信", ["46005"] = "中国电信", ["46011"] = "中国电信", ["46012"] = "中国电信",
  ["46015"] = "中国广电",
}) do
  eq("plmn " .. plmn, gw.carrier_from_imsi(plmn .. "0123456789"), want)
end
eq("unknown plmn -> nil", gw.carrier_from_imsi("460990123456789"), nil)
eq("nil imsi -> nil", gw.carrier_from_imsi(nil), nil)
eq("label with carrier", gw.sim_label("中国电信"), "SIM 1 · 中国电信")
eq("label without carrier", gw.sim_label(nil), "SIM 1")
eq("label separator bytes", hex(gw.sim_label("X")), hex("SIM 1") .. "20c2b720" .. hex("X"))

-- ---- no owner, no phone-number gate anywhere in gw.lua --------------------------
print("== no OWNER in gw.lua")
-- SMS commands are main.lua's and are authenticated with SMS_KEY, not with a caller
-- ID. gw.lua must not carry a second copy of that logic, nor read cfg.OWNER: a stale
-- duplicate here is exactly the divergence the collapse into main.lua removed.
ok("gw.lua exports no is_owner", gw.is_owner == nil)
ok("gw.lua mentions OWNER nowhere", not read_file(REPO .. "/gw.lua"):find("OWNER", 1, true))

-- ---- ack_detail / build_ack ------------------------------------------------------
print("== ack_detail")
eq("ok -> attempt id", gw.ack_detail("SEND_OK", "回执成功", "SMS-20260915-3f9a1c7e"), "SMS-20260915-3f9a1c7e")
local d = gw.ack_detail("SEND_TIMEOUT", "45s 内未收到回执", "SMS-20260915-3f9a1c7e")
eq("failure format", d, "SEND_TIMEOUT｜45s 内未收到回执 [SMS-20260915-3f9a1c7e]")
eq("separator is U+FF5C", hex(d:sub(13, 15)), "efbd9c")
eq("replay detail", gw.ack_detail("SEND_TIMEOUT", "此前已处理，重发请求已忽略", "replay"), "SEND_TIMEOUT｜此前已处理，重发请求已忽略 [replay]")
eq("build_ack ok", gw.build_ack(12, true, "SMS-20260915-abcdef01"), '{"id":12,"ok":true,"detail":"SMS-20260915-abcdef01"}')
eq("build_ack fail escapes", gw.build_ack(7, false, 'X｜a"b [r]'), '{"id":7,"ok":false,"detail":"X｜a\\"b [r]"}')
eq("attempt id shape", gw.new_attempt_id():match("^SMS%-%d%d%d%d%d%d%d%d%-%x%x%x%x%x%x%x%x$") ~= nil, true)
eq("attempt id hex is lowercase", gw.new_attempt_id():match("^SMS%-%d+%-(.*)$"):match("%u"), nil)

-- ---- done-ring --------------------------------------------------------------------
print("== ring")
eq("get on empty", gw.ring_get("", 5), nil)
eq("get on nil", gw.ring_get(nil, 5), nil)
local r = gw.ring_put("", 12, "SEND_OK")
eq("put first", r, "12=SEND_OK")
r = gw.ring_put(r, 13, "SEND_TIMEOUT")
eq("put second", r, "12=SEND_OK,13=SEND_TIMEOUT")
eq("get 12", gw.ring_get(r, 12), "SEND_OK")
eq("get 13", gw.ring_get(r, 13), "SEND_TIMEOUT")
eq("get missing", gw.ring_get(r, 14), nil)
eq("get prefix id does not match", gw.ring_get(r, 1), nil)
r = gw.ring_put(r, 12, "SEND_TIMEOUT")
eq("re-put moves to end", r, "13=SEND_TIMEOUT,12=SEND_TIMEOUT")
r = ""
for i = 1, 41 do r = gw.ring_put(r, i, "SEND_OK") end
eq("eviction keeps 40", select(2, r:gsub("=", "")), 40)
eq("oldest evicted", gw.ring_get(r, 1), nil)
eq("second oldest kept", gw.ring_get(r, 2), "SEND_OK")
eq("newest kept", gw.ring_get(r, 41), "SEND_OK")
ok("ring fits fskv", #r < 4095)
eq("blank entries ignored", gw.ring_get(",,5=X,,", 5), "X")

-- ---- parse_poll --------------------------------------------------------------------
print("== parse_poll")
local p = gw.parse_poll('{"status":"pending"}')
eq("pending: status", p and p.status, "pending")
eq("pending: no rows", p and #p.rows, 0)
eq("pending: no cmd", p and p.cmd, nil)
p = gw.parse_poll('{"status":"trusted","rows":[{"id":12,"payload":"v1:abc"},{"id":13,"payload":"v1:def"}],"cmd":null}')
eq("trusted: two rows", #p.rows, 2)
eq("row 1 id", p.rows[1].id, 12)
eq("row 1 payload", p.rows[1].payload, "v1:abc")
eq("row 2 id", p.rows[2].id, 13)
ok("id is an integer", math.type(p.rows[1].id) == "integer")
eq("json null cmd -> nil", p.cmd, nil)
p = gw.parse_poll('{"status":"trusted","rows":[{"id":5},{"payload":"v1:x"},{"id":"7","payload":"p"}],"cmd":{"id":3,"type":"ota","name":"gw","hmac":"ab"}}')
eq("missing payload -> empty string, non-integer ids skipped", #p.rows, 1)
eq("missing payload value", p.rows[1].payload, "")
eq("cmd parsed", p.cmd and p.cmd.type .. " " .. p.cmd.id .. " " .. p.cmd.name .. " " .. p.cmd.hmac, "ota 3 gw ab")
eq("cmd without id -> nil", gw.parse_poll('{"status":"trusted","cmd":{"type":"reboot"}}').cmd, nil)
eq("blocked without rows", gw.parse_poll('{"status":"blocked"}').status, "blocked")
eq("invalid JSON -> nil", gw.parse_poll("nope"), nil)
eq("array body (old /api/outbox shape) -> nil", gw.parse_poll("[]"), nil)
eq("object without status -> nil", gw.parse_poll('{"rows":[]}'), nil)
eq("truncated -> nil", gw.parse_poll('{"status":"trusted","rows":[{"id":1,'), nil)
eq("nil body -> nil", gw.parse_poll(nil), nil)
p = gw.parse_poll(' \n{ "status" : "trusted", "rows": [ {"id": 99 , "payload" : "v1:\\u4e2d" } ] }')
eq("whitespace and unicode escape", p.rows[1].payload, "v1:中")

-- ---- parse_bases ---------------------------------------------------------------------
-- status_line's utc=/win= track the real clock, so compute the expected suffix rather than
-- hardcoding an hour — otherwise this suite only passes between 06:00 and 07:00 UTC.
local function winsuf()
  local h = tonumber(os.date("!%H"))
  return string.format(" utc=%02d win=%s", h, (h >= 6 and h < 22) and "fast" or "slow")
end

print("== parse_bases")
local b = gw.parse_bases("https://a.com/, https://b.com ,ftp://x , http://127.0.0.1:8787/")
eq("bases count", #b, 3)
eq("base 1 trimmed", b[1], "https://a.com")
eq("base 3 http allowed", b[3], "http://127.0.0.1:8787")
b = gw.parse_bases({ "https://a.com/", "junk", "" })
eq("table input", #b, 1)
eq("nil input", #gw.parse_bases(nil), 0)

-- ---- dormant standalone start: callbacks only, no network tasks --------------------
-- gw.lua without main.lua (no identity in fskv): registers its callbacks and starts
-- nothing that talks to the network; inbound SMS/calls are dropped with a log.
print("== dormant start (no identity)")
do
  fskv.clear()
  fake.http_log = {}
  gw.start({ BASES = { "https://x.test" }, TOPIC = "sms-t", NAME = "Air780EHV", POLL_MS = 30000,
             SMS_KEY = ("00112233445566778899aabbccddeeff"):rep(2) })
  ok("GCM_OK true (key fine)", _G.GCM_OK == true)
  ok("not started without an identity", gw._state().started == false)
  fake.tick(120000)
  eq("no HTTP requests after 120 s", #fake.http_log, 0)
  fake.sms_incoming("10086", "dropped while dormant")
  fake.call_incoming("+8613900000000")
  fake.tick(1000)
  eq("inbound SMS/call dropped, still no HTTP", #fake.http_log, 0)
  eq("nothing persisted in the queue", fskv.get("qidx"), nil)
  fake.call_end(); fake.tick(10)
  -- Standalone (no main.lua): a "#" message is just a message. gw.lua answers nothing —
  -- the whole command channel lives in main.lua, behind the SMS_KEY signature.
  fake.sms_sent = {}
  fake.sms_incoming("+8613800138000", "#ota gw ab")
  fake.sms_incoming("+8613800138000", "#url https://h.test")
  fake.sms_incoming("+8613800138000", "#status")
  fake.tick(10)
  eq("standalone gw.lua answers no # command", #fake.sms_sent, 0)
  eq("and still talks to nobody", #fake.http_log, 0)
  fake.sms_sent = {}
end

-- ---- runtime through main.lua (fake scheduler, mocked Worker) -----------------------
print("== runtime (main.lua boot, mocked Worker)")
do
  local key_hex = ("00112233445566778899aabbccddeeff"):rep(2)
  local key32 = key_hex:fromHex()
  local PHONE = "+8613800138000"       -- any phone: the signature authenticates, not the number
  -- The SMS wire format main.lua verifies: "<body> <first 16 hex of HMAC(\"sms\\n\"+body)>".
  local function signed(body) return body .. " " .. crypto.hmac_sha256("sms\n" .. body, key32):sub(1, 16):lower() end
  local requests = {}
  local status, rows, cmd, upload_code, poll_code = "pending", "[]", "null", 200, 200
  local ota_files = {}
  local polls_seen = 0
  fake.http_mock = function(method, url, headers, body)
    requests[#requests + 1] = { method = method, url = url, headers = headers, body = body }
    if url:find("/api/register?", 1, true) and method == "POST" then return 200, {}, '{"status":"' .. status .. '"}' end
    if url:find("/api/poll?", 1, true) and method == "GET" then
      polls_seen = polls_seen + 1
      if poll_code ~= 200 then return poll_code, {}, "" end
      if status ~= "trusted" then return 200, {}, '{"status":"' .. status .. '"}' end
      return 200, {}, '{"status":"trusted","rows":' .. rows .. ',"cmd":' .. cmd .. '}'
    end
    if url:find("/api/outbox/ack", 1, true) or url:find("/api/cmd/ack", 1, true) then return 200, {}, '{"ok":true}' end
    if url:find("/api/ota/get?", 1, true) then
      local f = ota_files[url:match("name=(%a+)")]
      if f then return 200, {}, f end
      return 404, {}, "not found"
    end
    if url:find("/sms%-t", 1) then return upload_code, {}, "ok" end
    return 404, {}, "not found"
  end
  local function find(sub, method) local t = {}; for _, r in ipairs(requests) do if r.url:find(sub, 1, true) and (not method or r.method == method) then t[#t + 1] = r end end; return t end
  local function last(sub) local t = find(sub); return t[#t] end
  -- The poll phase drifts with every 45 s send wait, so the command tests tick up to the
  -- next poll instead of assuming one lands inside a 30 s window.
  local function next_poll() local n = polls_seen; repeat fake.tick(1000) until polls_seen > n end

  fskv.clear()
  fake.no_run = true
  fake.config = { BASES = { "https://x.test" }, TOPIC = "sms-t", SMS_KEY = key_hex, NAME = "Air780EHV", POLL_MS = 30000 }
  fake.reboot_cycle()
  local rt = require("gw")   -- the instance main.lua started
  local st = rt._state()
  ok("dev id is 16 lowercase hex", st.dev_id:match("^[0-9a-f]+$") ~= nil and #st.dev_id == 16)
  eq("dev id persisted", fskv.get("dev_id"), st.dev_id)
  local secret = fskv.get("dev_secret")
  ok("dev secret is 32 lowercase hex", type(secret) == "string" and secret:match("^[0-9a-f]+$") ~= nil and #secret == 32)
  ok("gcm selftest recorded", _G.GCM_OK == true)
  ok("network tasks started", st.started == true)

  -- Boot: register, then poll. Pending → no upload, nothing sent.
  fake.tick(10)
  eq("one register at boot", #find("/api/register"), 1)
  eq("one poll at boot", #find("/api/poll"), 1)
  local reg = find("/api/register")[1]
  eq("register url", reg.url, "https://x.test/api/register?dev=" .. st.dev_id)
  eq("register bearer is the device secret", reg.headers["Authorization"], "Bearer " .. secret)
  eq("register content-type", reg.headers["Content-Type"], "text/plain; charset=utf-8")
  eq("register blob decrypts to the exact self-description", gcm.open(key32, reg.body),
    '{"n":"Air780EHV","s":[{"slot":0,"name":"SIM 1 · 中国电信"}],"t":"4G","os":"LuatOS V2050 Air780EHV","v":"2.2.0","ls":""'
    .. ',"imei":"861234567890123","iccid":"89860012345678901234","imsi":"460110123456789","num":"","fw":"V2050","ver":"2.2.0","ota":"-","boot":1}')
  eq("poll url", find("/api/poll")[1].url, "https://x.test/api/poll?dev=" .. st.dev_id)
  eq("poll bearer", find("/api/poll")[1].headers["Authorization"], "Bearer " .. secret)
  eq("poll is a GET", find("/api/poll")[1].method, "GET")
  eq("trust = pending", rt._state().trust, "pending")
  ok("waiting-for-trust logged once", log_has("waiting for trust on the web"))
  requests = {}
  fake.sms_incoming("10086", "您的验证码是 123456")
  fake.tick(20000)
  eq("pending: message queued", #rt._state().queue, 1)
  eq("pending: nothing uploaded", #find("/sms-t"), 0)
  eq("pending: no devinfo any more", #find("/api/devinfo"), 0)
  eq("signed #status while pending", (function() fake.sms_sent = {}; fake.sms_incoming(PHONE, signed("#status")); fake.tick(10); return fake.sms_sent[1] and fake.sms_sent[1].body end)(),
    "2.2.0 csq=20 net=1 ip=10.0.0.2 q=1 gcm=ok fw=V2050 trust=pending ota=- boot=1 ws=off" .. winsuf())

  -- Trusted on the web: the next poll sees it → queue drains → re-register on the following cycle.
  status = "trusted"
  requests = {}
  fake.tick(11000)   -- t = 31 s: second poll
  eq("trusted: upload happened", #find("/sms-t"), 1)
  local up = find("/sms-t")[1]
  eq("upload url", up.url, "https://x.test/sms-t?dev=" .. st.dev_id)
  eq("upload method", up.method, "POST")
  eq("upload auth is the device secret", up.headers["Authorization"], "Bearer " .. secret)
  eq("upload content-type", up.headers["Content-Type"], "text/plain; charset=utf-8")
  eq("upload body decrypts to G5 shape", gcm.open(key32, up.body),
    '{"s":"10086","b":"您的验证码是 123456","k":"SIM 1 · 中国电信","d":"' .. st.dev_id .. '"}')
  eq("queue drained", #rt._state().queue, 0)
  eq("fskv queue index cleared", fskv.get("qidx"), nil)
  eq("trust = trusted", rt._state().trust, "trusted")
  eq("no re-register in the same cycle", #find("/api/register"), 0)
  fake.tick(30000)   -- t = 61 s
  eq("trust change observed by the poll → re-register next cycle", #find("/api/register"), 1)
  eq("re-register reports ls (still empty) and boot=1", gcm.open(key32, find("/api/register")[1].body):match('"ls":"","imei"') ~= nil, true)

  -- Missed call, debounced across repeated INCOMINGCALL.
  requests = {}
  fake.call_incoming("+8613900000000")
  fake.call_incoming("+8613900000000")
  fake.tick(10)
  eq("one missed-call upload", #find("/sms-t"), 1)
  eq("missed call body", gcm.open(key32, find("/sms-t")[1].body),
    '{"s":"+8613900000000","b":"未接来电","k":"SIM 1 · 中国电信","d":"' .. st.dev_id .. '"}')
  fake.call_end()
  fake.tick(10)
  eq("ringing cleared", rt._state().ringing, false)

  -- A signed command is executed and NOT forwarded; the rich line comes from gw.lua
  -- through _G.gw_status_line, which is the only thing gw.lua still contributes here.
  requests = {}
  fake.sms_sent = {}
  fake.sms_incoming(PHONE, signed("#status"))
  fake.tick(10)
  eq("signed command not uploaded", #find("/sms-t"), 0)
  eq("status reply sent", #fake.sms_sent, 1)
  eq("status reply exact", fake.sms_sent[1].body, "2.2.0 csq=20 net=1 ip=10.0.0.2 q=0 gcm=ok fw=V2050 trust=trusted ota=- boot=1 ws=off" .. winsuf())
  ok("the rich line is gw.lua's hook", type(_G.gw_status_line) == "function")
  eq("the hook is what answered", _G.gw_status_line(), fake.sms_sent[1].body)
  -- An UNSIGNED "#status" — from any number at all — is an ordinary message: gw.lua
  -- forwards it, so the probe shows up on the web page instead of being answered.
  requests = {}
  fake.sms_sent = {}
  fake.sms_incoming(PHONE, "#status")
  fake.sms_incoming("+8613800138001", "#status")
  fake.tick(10)
  eq("unsigned #status forwarded by gw.lua, never answered", #find("/sms-t") .. " " .. #fake.sms_sent, "2 0")

  -- Blocked: poll says so → uploads pause, queue keeps the message; trusted again → drains.
  status = "blocked"
  requests = {}
  fake.tick(30000)
  eq("blocked: trust flag", rt._state().trust, "blocked")
  ok("blocked logged", log_has("blocked on the web"))
  fake.sms_incoming("10086", "held while blocked")
  fake.tick(20000)
  eq("blocked: queued, not uploaded", #rt._state().queue .. " " .. #find("/sms-t"), "1 0")
  status = "trusted"
  fake.tick(30000)
  eq("trusted again: drained", #rt._state().queue, 0)

  -- Upload 403 (trust revoked between polls): keep the queue, retry after the backoff.
  upload_code = 403
  requests = {}
  fake.sms_incoming("10086", "403 me")
  fake.tick(100)
  eq("403: one attempt", #find("/sms-t"), 1)
  eq("403: still queued", #rt._state().queue, 1)
  ok("403: persisted in fskv", fskv.get("q:" .. rt._state().queue[1].seq) ~= nil)
  ok("403: treated as not trusted", rt._state().trusted == false)
  upload_code = 200
  fake.tick(60000)   -- backoff, next poll re-confirms trusted, uploader retries
  eq("403 then trusted: drained", #rt._state().queue, 0)

  -- Outbox: one row via the poll → send → ack ok; ring persisted.
  requests = {}
  fake.sms_sent = {}
  local row_plain = '{"to":"+8613800138000","body":"hello 你好","sim":""}'
  rows = '[{"id":42,"payload":"' .. gcm.seal(key32, row_plain) .. '"}]'
  fake.tick(30000)   -- next poll, SMS_SENT report 100 ms later
  eq("sms.send called once", #fake.sms_sent, 1)
  eq("sms to", fake.sms_sent[1].to, "+8613800138000")
  eq("sms body", fake.sms_sent[1].body, "hello 你好")
  local ackr = last("/api/outbox/ack")
  ok("ack posted", ackr ~= nil)
  eq("ack content-type", ackr and ackr.headers["Content-Type"], "application/json")
  eq("ack bearer", ackr and ackr.headers["Authorization"], "Bearer " .. secret)
  ok("ack body ok", ackr and ackr.body:match('^{"id":42,"ok":true,"detail":"SMS%-%d+%-%x+"}$') ~= nil)
  eq("ring persisted", fskv.get("done"), "42=SEND_OK")
  ok("last_send recorded", rt._state().last_send:match("^成功 %[SMS%-") ~= nil)

  -- Re-served row: no second send, re-ack with replay detail.
  requests = {}
  fake.sms_sent = {}
  fake.tick(30000)
  eq("no re-send", #fake.sms_sent, 0)
  eq("replay ack", last("/api/outbox/ack") and last("/api/outbox/ack").body, '{"id":42,"ok":true,"detail":"此前已处理，重发请求已忽略"}')

  -- Wrong-key row → OUTBOX_DECRYPT_FAILED, still acked, not in the ring.
  requests = {}
  rows = '[{"id":43,"payload":"' .. gcm.seal(string.rep("\1", 32), row_plain) .. '"}]'
  fake.tick(30000)
  ackr = last("/api/outbox/ack")
  ok("decrypt failure acked", ackr and ackr.body:match('^{"id":43,"ok":false,"detail":"OUTBOX_DECRYPT_FAILED｜') ~= nil)
  eq("decrypt failure not in ring", gw.ring_get(fskv.get("done"), 43), nil)

  -- Oversized payload → rejected before the pure-Lua decrypt, still acked failed.
  requests = {}
  fake.sms_sent = {}
  rows = '[{"id":46,"payload":"v1:' .. string.rep("A", 5000) .. '"}]'
  fake.tick(30000)
  eq("oversized not sent", #fake.sms_sent, 0)
  ackr = last("/api/outbox/ack")
  ok("oversized acked decrypt-failed", ackr and ackr.body:match('^{"id":46,"ok":false,"detail":"OUTBOX_DECRYPT_FAILED｜密文过大') ~= nil)
  eq("oversized not in ring", gw.ring_get(fskv.get("done"), 46), nil)
  rows = "[]"

  -- Other SIM requested → SEND_SUBSCRIPTION_UNAVAILABLE without sending.
  requests = {}
  fake.sms_sent = {}
  rows = '[{"id":44,"payload":"' .. gcm.seal(key32, '{"to":"+8613800138000","body":"x","sim":"1"}') .. '"}]'
  fake.tick(30000)
  eq("sim 1 not sent", #fake.sms_sent, 0)
  ackr = last("/api/outbox/ack")
  ok("sim 1 acked as unavailable", ackr and ackr.body:match('"ok":false,"detail":"SEND_SUBSCRIPTION_UNAVAILABLE｜') ~= nil)

  -- Timeout → SEND_TIMEOUT enters the ring (a timed-out send may have gone out).
  requests = {}
  fake.sms_sent = {}
  fake.sms_mode = "timeout"
  rows = '[{"id":45,"payload":"' .. gcm.seal(key32, '{"to":"+8613800138000","body":"x","sim":"0"}') .. '"}]'
  fake.tick(30000 + 46000)
  eq("timeout send attempted", #fake.sms_sent, 1)
  eq("timeout in ring", gw.ring_get(fskv.get("done"), 45), "SEND_TIMEOUT")
  fake.sms_mode = "ok"
  rows = "[]"

  -- Busy: after a timed-out send the modem still owes SMS_SENT, so the next
  -- sms.send returns nil. gw must drain that report and retry once, not ack a
  -- failure for a message it never attempted.
  requests = {}
  fake.sms_sent = {}
  fake.sms_mode = "busy_once"
  rows = '[{"id":47,"payload":"' .. gcm.seal(key32, '{"to":"+8613800138000","body":"after busy","sim":""}') .. '"}]'
  fake.tick(30000)
  eq("busy then retried", #fake.sms_sent, 2)
  eq("retry body", fake.sms_sent[2].body, "after busy")
  ackr = last("/api/outbox/ack")
  ok("busy row acked ok", ackr and ackr.body:match('^{"id":47,"ok":true,') ~= nil)
  eq("busy row in ring", gw.ring_get(fskv.get("done"), 47), "SEND_OK")
  fake.sms_mode = "ok"
  rows = "[]"

  -- Upload retry: 5xx → backoff → success; 4xx (not 403) → drop.
  requests = {}
  upload_code = 503
  fake.sms_incoming("10010", "retry me")
  fake.tick(100)
  eq("first attempt failed", #find("/sms-t"), 1)
  eq("still queued", #rt._state().queue, 1)
  ok("persisted in fskv", fskv.get("q:" .. rt._state().queue[1].seq) ~= nil)
  upload_code = 200
  fake.tick(15000)
  eq("retried after 15 s", #find("/sms-t"), 2)
  eq("drained after success", #rt._state().queue, 0)
  requests = {}
  upload_code = 404
  fake.sms_incoming("10010", "drop me")
  fake.tick(100)
  eq("4xx attempted once", #find("/sms-t"), 1)
  eq("4xx dropped", #rt._state().queue, 0)
  fake.tick(60000)
  eq("4xx never retried", #find("/sms-t"), 1)
  upload_code = 200

  -- ---- web commands from the poll --------------------------------------------------
  print("== web commands")
  -- reboot: acked (ok, "rebooting") BEFORE the reboot, boot_fail cleared, reboot after 5 s.
  fskv.set("boot_fail", 2)
  requests = {}
  cmd = '{"id":1,"type":"reboot"}'
  next_poll()
  local cack = last("/api/cmd/ack")
  eq("reboot acked", cack and cack.body, '{"id":1,"ok":true,"detail":"rebooting"}')
  eq("cmd ack content-type", cack and cack.headers["Content-Type"], "application/json")
  eq("cmd ack bearer", cack and cack.headers["Authorization"], "Bearer " .. secret)
  eq("reboot cleared boot_fail", fskv.get("boot_fail"), 0)
  ok("acked, not yet rebooted", not fake.rebooted)
  fake.tick(5000)
  ok("rebooted 5 s after the ack", fake.rebooted)
  eq("last_cmd stored", fskv.get("last_cmd"), 1)
  eq("last_cmd_res stored", fskv.get("last_cmd_res"), "ok:rebooting")
  -- Dedupe across a reboot: the Worker still serves cmd 1 (its ack got lost) → re-acked, not re-run.
  requests = {}
  fake.reboot_cycle(); rt = require("gw")
  fake.tick(10)
  cack = last("/api/cmd/ack")
  eq("re-served cmd re-acked with the stored result", cack and cack.body, '{"id":1,"ok":true,"detail":"rebooting"}')
  ok("re-acked logged as already ran", log_has("cmd #1 already ran"))
  fake.tick(20000)
  ok("not re-run: no second reboot", not fake.rebooted)
  cmd = "null"

  -- bases: a poll-delivered one must be signed with SMS_KEY (MAC over "bases\n" .. the value AS
  -- SENT), because it is the one command that can move the module to a server the real Worker
  -- can never reach — an unsigned one would let an on-path attacker (TLS verification is off by
  -- default) or a compromised Worker capture it permanently. Unsigned / wrongly signed → "hmac",
  -- nothing stored; invalid → "bad bases"; valid + signed → fskv + ack + reboot; next boot polls it.
  local function bmac(v) return crypto.hmac_sha256("bases\n" .. v, key32) end
  requests = {}
  cmd = '{"id":20,"type":"bases","value":"https://evil.test"}'
  next_poll()
  eq("unsigned bases acked hmac", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":20,"ok":false,"detail":"hmac"}')
  eq("unsigned bases stored nothing", fskv.get("bases"), nil)
  ok("unsigned bases: no reboot", not fake.rebooted)
  requests = {}
  cmd = '{"id":21,"type":"bases","value":"https://evil.test","hmac":"' .. ("0"):rep(64) .. '"}'
  next_poll()
  eq("wrong-hmac bases acked hmac", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":21,"ok":false,"detail":"hmac"}')
  eq("wrong-hmac bases stored nothing", fskv.get("bases"), nil)
  requests = {}
  cmd = '{"id":22,"type":"bases","value":"https://evil.test","hmac":"' .. bmac("https://a.test") .. '"}'
  next_poll()
  eq("value swapped under a good signature acked hmac", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":22,"ok":false,"detail":"hmac"}')
  eq("swapped-value bases stored nothing", fskv.get("bases"), nil)
  requests = {}
  cmd = '{"id":2,"type":"bases","value":"http://plain.test","hmac":"' .. bmac("http://plain.test") .. '"}'
  next_poll()
  eq("bad bases acked failed", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":2,"ok":false,"detail":"bad bases"}')
  eq("bad bases stored nothing", fskv.get("bases"), nil)
  ok("bad bases: no reboot", not fake.rebooted)
  local GOODV = "https://a.test, https://b.test:8443/x/"
  cmd = '{"id":3,"type":"bases","value":"' .. GOODV .. '","hmac":"' .. bmac(GOODV) .. '"}'
  requests = {}
  next_poll()
  eq("bases acked ok", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":3,"ok":true,"detail":"rebooting"}')
  eq("bases stored normalised", fskv.get("bases"), "https://a.test,https://b.test:8443/x")
  ok("bases: acked, not yet rebooted", not fake.rebooted)
  fake.tick(5000)
  ok("bases: rebooted", fake.rebooted)
  cmd = "null"
  requests = {}
  fake.reboot_cycle(); rt = require("gw")
  fake.tick(10)
  eq("next boot registers at the new base", find("/api/register")[1].url:match("^https://a%.test/") ~= nil, true)
  eq("_state().bases follows fskv", table.concat(rt._state().bases, ","), "https://a.test,https://b.test:8443/x")
  fskv.del("bases")
  fake.reboot_cycle(); rt = require("gw")
  fake.tick(10)

  -- ota: the staged script comes from the Worker; name-bound HMAC; install → ack "<bytes>" → reboot 10 s.
  local src = assert(read_file(REPO .. "/gw.lua"))
  local mod = src:gsub("\nreturn M%s*$", '\n_G.GW_TAG = "ota"\nreturn M\n')
  ok("modified gw.lua differs", mod ~= src)
  ota_files.gw = mod
  local function mac(name, body) return crypto.hmac_sha256(name .. "\n" .. body, key32) end
  requests = {}
  cmd = '{"id":4,"type":"ota","name":"gw","hmac":"' .. mac("gcm", mod) .. '"}'
  next_poll()
  eq("wrong-slot signature (signed for gcm) → hmac fail", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":4,"ok":false,"detail":"hmac"}')
  eq("wrong slot → no file", _G.gw_ota.active(), "-")
  cmd = '{"id":5,"type":"ota","name":"gcm","hmac":"' .. mac("gcm", mod) .. '"}'
  next_poll()
  eq("not staged on the Worker → http 404", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":5,"ok":false,"detail":"http 404"}')
  ota_files.gcm = "this is not lua ("
  cmd = '{"id":6,"type":"ota","name":"gcm","hmac":"' .. mac("gcm", ota_files.gcm) .. '"}'
  next_poll()
  eq("bad body, right hmac → compile", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":6,"ok":false,"detail":"compile"}')
  ota_files.gcm = ""
  cmd = '{"id":7,"type":"ota","name":"gcm","hmac":"' .. mac("gcm", "") .. '"}'
  next_poll()
  eq("empty body → size", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":7,"ok":false,"detail":"size"}')
  ota_files.gcm = nil
  eq("nothing installed so far", _G.gw_ota.active(), "-")
  fskv.set("boot_fail", 1)
  requests = {}
  cmd = '{"id":8,"type":"ota","name":"gw","hmac":"' .. mac("gw", mod):upper() .. '"}'
  next_poll()
  local get = last("/api/ota/get")
  eq("ota download url", get and get.url, "https://x.test/api/ota/get?dev=" .. st.dev_id .. "&name=gw")
  eq("ota download bearer", get and get.headers["Authorization"], "Bearer " .. secret)
  eq("good install acked with the byte count (uppercase hmac accepted)", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":8,"ok":true,"detail":"' .. #mod .. '"}')
  eq("/ota_gw.lua written byte-exact", read_file(fake.fs_root .. "/ota_gw.lua"), mod)
  eq("install resets boot_fail", fskv.get("boot_fail"), 0)
  ok("acked, not yet rebooted", not fake.rebooted)
  fake.tick(10000)
  ok("rebooted 10 s later", fake.rebooted)
  cmd = "null"
  requests = {}
  fake.reboot_cycle(); rt = require("gw")
  fake.tick(10)
  eq("OTA gw runs after the reboot", _G.GW_TAG, "ota")
  eq("register now reports ota=gw", gcm.open(key32, find("/api/register")[1].body):match('"ota":"gw"') ~= nil, true)
  eq("signed #status shows ota=gw", (function() fake.sms_sent = {}; fake.sms_incoming(PHONE, signed("#status")); fake.tick(10); return fake.sms_sent[1] and fake.sms_sent[1].body end)(),
    "2.2.0 csq=20 net=1 ip=10.0.0.2 q=0 gcm=ok fw=V2050 trust=trusted ota=gw boot=1 ws=off" .. winsuf())
  _G.GW_TAG = nil

  -- ---- the web pressed 忘记: the devices row is gone --------------------------------
  print("== poll 403/404 → re-register")
  -- /api/poll cannot recreate the row (deviceAuth 403s before anything else runs);
  -- only /api/register can. So a definitive auth answer must schedule one instead of
  -- being treated as an ordinary network failure (which would go dark for up to 30 min).
  poll_code = 403
  requests = {}
  next_poll()
  eq("403 poll: no register inside the same cycle", #find("/api/register"), 0)
  ok("403 poll logged as a failure", log_has("poll failed"))
  poll_code = 200
  requests = {}
  next_poll()
  eq("403 → re-registers on the next cycle", #find("/api/register"), 1)
  eq("the re-register is a POST to /api/register", find("/api/register")[1].method, "POST")
  poll_code = 404
  requests = {}
  next_poll()
  poll_code = 200
  requests = {}
  next_poll()
  eq("404 → re-registers too", #find("/api/register"), 1)
  poll_code = 500
  requests = {}
  next_poll()
  poll_code = 200
  requests = {}
  next_poll()
  eq("a 500 is an ordinary failure: no forced re-register", #find("/api/register"), 0)

  -- ---- gw.lua no longer handles "#" at all ------------------------------------------
  print("== gw.lua forwards # messages")
  -- Everything the old control() did now lives in main.lua behind the SMS_KEY signature
  -- (test_main.lua covers the whole command matrix). What has to be true HERE is that
  -- gw.lua treats an unsigned "#" like any other SMS — even with a stale cfg.OWNER left
  -- in someone's config.lua — and that a signed one never reaches it at all.
  fake.fs_clear()
  fake.config.OWNER = PHONE
  fake.reboot_cycle(); rt = require("gw")
  fake.tick(10)
  requests = {}
  fake.sms_sent = {}
  fake.sms_incoming(PHONE, "#status")
  fake.sms_incoming(PHONE, "#reboot")
  fake.tick(100)
  eq("a stale cfg.OWNER changes nothing: both forwarded, neither answered", #find("/sms-t") .. " " .. #fake.sms_sent, "2 0")
  ok("an unsigned #reboot does not reboot", not fake.rebooted)
  fake.config.OWNER = nil
  requests = {}
  fake.sms_sent = {}
  fake.sms_incoming(PHONE, signed("#status"))
  fake.tick(100)
  eq("its signed twin is answered by main.lua and not forwarded", #find("/sms-t") .. " " .. #fake.sms_sent, "0 1")
  fake.http_mock = nil
end

-- ---- SMS_KEY validation: a bad key disables uploads (never a zero-key fallback)
-- gw.start wires callbacks + taskInit but does not run the scheduler, so these
-- extra starts stay dormant (no tick follows) and only GCM_OK is observed.
print("== bad SMS_KEY disables uploads")
do
  local base = { BASES = { "https://x.test" }, TOPIC = "sms-t", POLL_MS = 30000 }
  base.SMS_KEY = "not-64-hex-at-all"
  gw.start(base)
  ok("GCM_OK false on non-hex key", _G.GCM_OK == false)
  ok("not started on a bad key", gw._state().started == false)
  base.SMS_KEY = string.rep("0", 64)
  gw.start(base)
  ok("GCM_OK false on all-zero key", _G.GCM_OK == false)
  base.SMS_KEY = ("00112233445566778899aabbccddeeff"):rep(2)
  gw.start(base)
  ok("GCM_OK true on a valid key", _G.GCM_OK == true)
end

-- =============================================================================
print("== poll schedule: the UTC window, the boot warm-up, and every failure path")
do
  -- 1789999380 = 2026-09-21 14:03:00 UTC. The module's own clock is UTC (its boot log's
  -- TIME_SYNC value decodes to UTC while China read 22:03), so the window is read straight
  -- off os.time() with no zone maths.
  local H = 3600
  local T14, T23, T04, T06 = 1789999380, 1789999380 + 9*H, 1789999380 + 14*H, 1789999380 + 16*H
  local FAR = 24 * H * 1000     -- well past BOOT_FAST_MS
  local FAST = gw.poll_interval(T14, FAR)
  eq("14:00 UTC is the fast tier", FAST, 30000)          -- cfg.POLL_MS from this suite's config
  eq("23:00 UTC is the slow tier", gw.poll_interval(T23, FAR), 600000)
  eq("04:00 UTC is the slow tier", gw.poll_interval(T04, FAR), 600000)
  eq("06:00 UTC is fast again (window is inclusive at 6)", gw.poll_interval(T06, FAR), FAST)
  -- The boot warm-up is what keeps the first poll of every boot close enough together to
  -- satisfy main.lua's ALIVE_MAX_MS gate even if that first attempt fails at 3 a.m.
  eq("boot warm-up overrides the slow tier at 0 ms", gw.poll_interval(T23, 0), FAST)
  eq("boot warm-up still applies at 9m59s", gw.poll_interval(T23, 599999), FAST)
  eq("boot warm-up ends at 10 min", gw.poll_interval(T23, 600000), 600000)
  -- Every failure path must fail FAST: being wrong in the expensive direction keeps the
  -- module reachable; being wrong in the cheap direction hides it for ten minutes at a time.
  eq("clock not yet NITZ-synced → fast", gw.poll_interval(0, FAR), FAST)
  eq("nil clock → fast", gw.poll_interval(nil, FAR), FAST)
  eq("NaN clock → fast", gw.poll_interval(0/0, FAR), FAST)
  eq("nil up_ms is not treated as a warm-up", gw.poll_interval(T23, nil), 600000)
end

-- =============================================================================
-- upload_once and register have always walked targets(serving or …); poll_once walked the raw
-- bases list. A bases[1] that is dead-but-answering (a parked page, a CF error page, a captive
-- portal — all realistic for a .xyz resolved from China) then made EVERY poll pay for a wasted
-- connection first: poll_once still returned true, poll_fail still reset, no guard fired, and the
-- monthly bill quietly doubled.
print("== poll_once prefers the serving base")
do
  local key_hex = ("00112233445566778899aabbccddeeff"):rep(2)
  local reqs = {}
  fake.http_mock = function(method, url)
    reqs[#reqs + 1] = { method = method, url = url }
    if url:find("bad.test", 1, true) then return 200, {}, "<html>domain for sale</html>" end
    if url:find("/api/register", 1, true) then return 200, {}, '{"status":"trusted"}' end
    if url:find("/api/poll", 1, true) then return 200, {}, '{"status":"trusted","rows":[],"cmd":null}' end
    return 404, {}, "not found"
  end
  local function polls_to(host)
    local n = 0
    for _, r in ipairs(reqs) do
      if r.url:find("/api/poll", 1, true) and r.url:find(host, 1, true) then n = n + 1 end
    end
    return n
  end
  fskv.clear()
  fake.no_run = true
  fake.config = { BASES = { "https://bad.test", "https://good.test" }, TOPIC = "sms-t",
                  SMS_KEY = key_hex, NAME = "Air780EHV", POLL_MS = 30000 }
  fake.reboot_cycle()
  fake.tick(35000)
  ok("first poll has to try the dead base", polls_to("bad.test") >= 1)
  ok("and falls through to the one that answers properly", polls_to("good.test") >= 1)
  reqs = {}
  fake.tick(35000)
  local first
  for _, r in ipairs(reqs) do
    if r.url:find("/api/poll", 1, true) then first = r.url; break end
  end
  ok("the next poll goes straight to the serving base", first ~= nil and first:find("good.test", 1, true) ~= nil)
  eq("and pays for exactly one connection", polls_to("bad.test"), 0)
  fake.http_mock = nil
end

-- =============================================================================
print("== ws_frame / ws_parse")
eq("frame: one JSON line, then the raw body",
  gw.ws_frame(7, "POST", "/sms-t?dev=ab", "Bearer s", "text/plain; charset=utf-8", "v1:x\ny"),
  '{"i":7,"m":"POST","p":"/sms-t?dev=ab","a":"Bearer s","t":"text/plain; charset=utf-8"}\nv1:x\ny')
eq("frame: GET, no content type, no body",
  gw.ws_frame(1, "GET", "/api/poll?dev=ab", "Bearer s", nil, nil),
  '{"i":1,"m":"GET","p":"/api/poll?dev=ab","a":"Bearer s","t":""}\n')
do
  local m, b = gw.ws_parse('{"i":3,"c":200,"k":0,"n":1}\n{"status":"x"}\nmore')
  eq("parse: status", m.c, 200)
  eq("parse: body keeps its own newlines", b, '{"status":"x"}\nmore')
  local p, pb = gw.ws_parse('{"t":"poll"}')
  eq("parse: a poke has no body", p.t .. "|" .. pb, "poll|")
  eq("parse: not a frame", gw.ws_parse("HTTP/1.1 403"), nil)
end

-- =============================================================================
-- The socket is only ever a cheaper pipe for the same requests: up → everything goes through it
-- and a poke polls at once; any failure → the identical request over HTTPS; down → HTTPS on the
-- old schedule while reconnects back off.
print("== websocket first, HTTPS as the fallback")
do
  local key_hex = ("00112233445566778899aabbccddeeff"):rep(2)
  fake.http_mock = function(method, url)
    if url:find("/api/register", 1, true) then return 200, {}, '{"status":"trusted"}' end
    if url:find("/api/poll", 1, true) then return 200, {}, '{"status":"trusted","rows":[],"cmd":null}' end
    if url:find("/sms%-t%?") then return 200, {}, "ok" end
    return 404, {}, "not found"
  end
  local function https(sub) local n = 0; for _, r in ipairs(fake.http_log) do if r.url:find(sub, 1, true) then n = n + 1 end end; return n end
  local function tunnelled(sub) local n = 0; for _, f in ipairs(fake.ws_log) do if f:find(sub, 1, true) then n = n + 1 end end; return n end
  fake.ws_install()
  fake.http_log = {}
  fskv.clear()
  fake.no_run = true
  fake.config = { BASES = { "https://x.test" }, TOPIC = "sms-t", SMS_KEY = key_hex, NAME = "Air780EHV", POLL_MS = 30000 }
  fake.reboot_cycle()
  fake.tick(5000)
  local rt = require("gw")
  local st = rt._state()
  ok("socket up", st.ws_up)
  eq("one connection", fake.ws_connects, 1)
  eq("to the base, as wss, with ?dev=", fake.ws_live.url, "wss://x.test/api/ws?dev=" .. st.dev_id)
  eq("the poll's bearer on the upgrade", fake.ws_live.hdrs.Authorization, "Bearer " .. fskv.get("dev_secret"))
  eq("60 s protocol ping", fake.ws_live.keepalive, 60)
  ok("coming up pokes a poll through the tunnel", tunnelled("/api/poll?dev=" .. st.dev_id) >= 1)
  ok("#status says ws=up", _G.gw_status_line():find(" ws=up ", 1, true) ~= nil)

  local h0 = #fake.http_log
  local t0 = tunnelled("/api/poll")
  fake.tick(600000)
  eq("no HTTPS at all while the socket is up", #fake.http_log, h0)
  eq("polls every 5 min over it (not every 30 s)", tunnelled("/api/poll") - t0, 2)

  local p0 = rt._state().polls
  fake.ws_part = 7     -- the reply arrives in 7-byte pieces
  fake.ws_push()
  fake.tick(5000)
  eq("a poke polls within seconds, pieces reassembled", rt._state().polls, p0 + 1)
  fake.ws_part = 2000

  fake.sms_incoming("10086", "via the socket")
  fake.tick(2000)
  eq("inbound SMS uploaded through the tunnel", tunnelled("/sms-t?dev="), 1)
  ok("with its content type", fake.ws_log[#fake.ws_log]:find('"t":"text/plain; charset=utf-8"}\nv1:', 1, true) ~= nil)
  eq("and not over HTTPS", https("/sms-t"), 0)
  eq("queue drained", #rt._state().queue, 0)

  fake.ws_decline = true
  fake.sms_incoming("10086", "declined")
  fake.tick(2000)
  eq("Hub says c=0 → the same upload over HTTPS", https("/sms-t"), 1)
  ok("a decline does not drop the socket", rt._state().ws_up)
  fake.ws_decline = false

  fake.ws_silent = true   -- half-open TCP: frames go out, nothing ever comes back
  fake.sms_incoming("10086", "half-open")
  fake.tick(12000)
  eq("no reply within the timeout → HTTPS", https("/sms-t"), 2)
  eq("nothing lost on the way", #rt._state().queue, 0)
  ok("and the silent socket is dropped", not rt._state().ws_up)
  fake.ws_silent = false
  fake.tick(35000)
  ok("reconnects after the 30 s backoff (it had been up > 10 min)", rt._state().ws_up)
  eq("second connection", fake.ws_connects, 2)

  fake.ws_refuse = true
  local c0, hp0 = fake.ws_connects, https("/api/poll")
  fake.ws_drop()
  fake.tick(3600000)
  local tries = fake.ws_connects - c0
  ok("refused reconnects back off: " .. tries .. " tries in an hour", tries >= 4 and tries <= 6)
  ok("HTTPS polls carry on meanwhile", https("/api/poll") - hp0 >= 60)
  ok("#status says ws=down", _G.gw_status_line():find(" ws=down ", 1, true) ~= nil)
  fake.ws_refuse = false

  fake.config.CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
  fake.reboot_cycle()
  c0 = fake.ws_connects
  fake.tick(60000)
  ok("CA_PEM set → HTTPS only (websocket.create cannot verify)", rt ~= require("gw") and not require("gw")._state().ws_on)
  eq("no connection attempted", fake.ws_connects, c0)
  fake.config.CA_PEM = nil
  fake.config.WS = false
  fake.reboot_cycle()
  fake.tick(60000)
  ok("WS = false → HTTPS only", not require("gw")._state().ws_on)
  fake.config.WS = nil

  fake.ws_uninstall()
  fake.http_mock = nil
end

fake.fs_destroy()
print(string.format("\n%d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
