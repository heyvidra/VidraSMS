-- test_main.lua — boots the REAL main.lua under test/fake_luatos.lua (config.lua
-- served from fake.config, the Worker mocked) and walks the "flash once, never
-- again" life cycle:
--   0. no config.lua / bad SMS_KEY: nothing starts, logs every 60 s, #status if OWNER
--   1. config.lua: identity minted, register at boot, trust gating, health rule
--   2. web reboot cmd: ack before reboot, last_cmd dedupe across a reboot_cycle
--   3. web ota cmd: install, wdt armed before the chunk, broken copies removed at boot
--   4. OTA gw that crashes in start → reverted after 3 failed boots
--   5. liveness: OTA gw that polls nothing → reverted after 3 cycles; flashed gw
--      offline for an hour → never rebooted and never walked into rescue mode;
--      an OTA gw that can never reach the Worker still reverted
--   6. flashed gw that crashes → rescue mode: registers, polls, runs an ota cmd
--      from the mock and recovers; retry timing; OWNER SMS in rescue; fskv.get raising
--   7. degraded hardware: TRNG that fails, fskv that cannot persist the identity,
--      a boot counter that can be neither written nor erased
-- Run: lua luatos/test/test_main.lua

local here = debug.getinfo(1, "S").source:match("^@(.*)/[^/]*$") or "."
package.path = here .. "/?.lua;" .. here .. "/../?.lua;" .. package.path
local REPO = here .. "/.."

local fake = require("fake_luatos")
fake.quiet = true
fake.no_run = true        -- sys.run() returns; the test drives virtual time with fake.tick
fake.no_config = true     -- until a section installs fake.config
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
local function write_file(p, d) local f = assert(io.open(p, "wb")); f:write(d); f:close() end
local function run(cmd) local p = assert(io.popen(cmd, "r")); local out = p:read("a"); p:close(); return out end
local function ota_file(name) return read_file(fake.fs_root .. "/ota_" .. name .. ".lua") end
local function last_sms() local m = fake.sms_sent[#fake.sms_sent]; return m and m.body end
local function log_has(s) for _, l in ipairs(fake.log_lines) do if l:find(s, 1, true) then return true end end return false end
local function log_count(s) local n = 0; for _, l in ipairs(fake.log_lines) do if l:find(s, 1, true) then n = n + 1 end end; return n end

-- ---- fixtures ------------------------------------------------------------------
local OWNER, STRANGER = "+8613800138000", "+8613900000000"
local KEY1 = ("00112233445566778899aabbccddeeff"):rep(2)
local key1raw = KEY1:fromHex()
local UPLOAD_PATH = "/sms-7f3a9c2b1e0d?dev="        -- baked-in default TOPIC
local BASE = "https://777310753.xyz"                 -- first baked-in default base
local function ota_mac(name, body) return crypto.hmac_sha256(name .. "\n" .. body, key1raw) end
local CONFIG = { SMS_KEY = KEY1, OWNER = OWNER }     -- everything else = main.lua DEFAULTS

-- The mocked Worker: register/poll answer `status`; a trusted poll carries `rows` + `cmd`;
-- /api/ota/get serves `ota_files`; `offline` makes every request fail like no network.
local requests, ota_files = {}, {}
local status, rows, cmd, upload_code, offline = "trusted", "[]", "null", 200, false
local polls_seen, cmd_id = 0, 100
fake.http_mock = function(method, url, headers, body)
  requests[#requests + 1] = { method = method, url = url, headers = headers, body = body }
  if offline then return -4, {}, "" end
  if url:find("/api/register?", 1, true) then return 200, {}, '{"status":"' .. status .. '"}' end
  if url:find("/api/poll?", 1, true) and method == "GET" then
    polls_seen = polls_seen + 1
    if status ~= "trusted" then return 200, {}, '{"status":"' .. status .. '"}' end
    return 200, {}, '{"status":"trusted","rows":' .. rows .. ',"cmd":' .. cmd .. '}'
  end
  if url:find("/api/outbox/ack", 1, true) or url:find("/api/cmd/ack", 1, true) then return 200, {}, '{"ok":true}' end
  if url:find("/api/ota/get?", 1, true) then
    local f = ota_files[url:match("name=(%a+)")]
    if f then return 200, {}, f end
    return 404, {}, "not found"
  end
  if url:find(UPLOAD_PATH, 1, true) then return upload_code, {}, "ok" end
  return 404, {}, "not found"
end
local function find(sub) local t = {}; for _, r in ipairs(requests) do if r.url:find(sub, 1, true) then t[#t + 1] = r end end; return t end
local function last(sub) local t = find(sub); return t[#t] end
local function polls() return #find("/api/poll?") end
local function next_poll() local n = polls_seen; repeat fake.tick(1000) until polls_seen > n end
local function boot()
  requests, fake.sms_sent, _G.GW_TAG = {}, {}, nil
  fake.reboot_cycle()
end
local function dev() return fskv.get("dev_id") end
local function inbound(sender, body) return '{"s":"' .. sender .. '","b":"' .. body .. '","k":"SIM 1 · 中国电信","d":"' .. dev() .. '"}' end
local function sms_reply(from, text)
  fake.sms_sent = {}
  fake.sms_incoming(from, text)
  fake.tick(100)
  return last_sms()
end
-- Queue a web command for the next poll and run it; returns the ack body.
local function web_cmd(payload)
  cmd_id = cmd_id + 1
  cmd = '{"id":' .. cmd_id .. ',' .. payload .. '}'
  requests = {}
  next_poll()
  cmd = "null"
  local a = last("/api/cmd/ack")
  return a and a.body, cmd_id
end
local function reg_json(sim, ls, ota, bootn)
  return '{"n":"Air780EHV","s":[{"slot":0,"name":"' .. sim .. '"}],"t":"4G","os":"LuatOS V2050 Air780EHV","v":"2.0.0","ls":"' .. ls .. '"'
    .. ',"imei":"861234567890123","iccid":"89860012345678901234","imsi":"460110123456789","num":"","fw":"V2050","ver":"2.0.0","ota":"' .. ota .. '","boot":' .. bootn .. '}'
end

-- =============================================================================
print("== 0. no config.lua / bad SMS_KEY: nothing runs, logs every 60 s")
boot()
eq("boot_fail counted", fskv.get("boot_fail"), 1)
ok("no config.lua", package.loaded["config"] == nil)
ok("wdt armed by main.lua", _G.WDT_ARMED == true)
ok("identity minted anyway", (fskv.get("dev_id") or ""):match("^[0-9a-f]+$") ~= nil and #fskv.get("dev_secret") == 32)
ok("GCM_OK false", _G.GCM_OK == false)
ok("missing config logged", log_has("config.lua missing/invalid"))
fake.tick(180000)
eq("no HTTP after 3 min", #requests, 0)
ok("nagged again every 60 s", log_count("config.lua missing/invalid") >= 4)
fake.sms_incoming(OWNER, "#status")
fake.sms_incoming("10086", "dropped: nothing to encrypt with")
fake.call_incoming("+8613700000000")
fake.tick(100)
eq("no OWNER: #status not answered", #fake.sms_sent, 0)
eq("SMS/call dropped, no HTTP", #requests, 0)
fake.call_end(); fake.tick(10)
fake.tick(20 * 60000)
ok("never alive, no OTA: main.lua never reboots", not fake.rebooted)
eq("boot_fail untouched (never alive)", fskv.get("boot_fail"), 1)
fake.config = { SMS_KEY = "not-a-key", OWNER = OWNER }
boot()
ok("bad key logged as invalid config", log_has("config.lua missing/invalid"))
fake.tick(60000)
eq("bad key: no HTTP", #requests, 0)
ok("bad key + OWNER: main.lua answers #status",
  (sms_reply(OWNER, "#status") or ""):match("^RESCUE boot_fail=2 ota=%- fw=V2050 ver=2%.0%.0 dev=[0-9a-f]+$") ~= nil)
eq("stranger #status ignored", sms_reply(STRANGER, "#status"), nil)
fake.config = { SMS_KEY = ("0"):rep(64), OWNER = OWNER }
boot()
fake.tick(60000)
eq("all-zero key: no HTTP", #requests, 0)
fskv.clear(); fake.fs_clear()

-- =============================================================================
print("== 1. config.lua: identity, register at boot, trust gating, health rule")
fake.config = CONFIG
status = "pending"
boot()
fake.tick(10)
eq("boot_fail 1", fskv.get("boot_fail"), 1)
local secret = fskv.get("dev_secret")
ok("dev_secret is 32 lowercase hex", type(secret) == "string" and #secret == 32 and secret:match("^[0-9a-f]+$") ~= nil)
-- main.lua must NOT write into the `sms` library object: on firmware it is a rotable
-- userdata with no __newindex and the assignment would kill the boot. It shadows the
-- global with a proxy instead, so sms.send & co still resolve through __index.
do
  local rot = getmetatable(sms) and getmetatable(sms).__index
  ok("sms is main.lua's proxy, not the library object", rawget(sms, "setNewSmsCb") ~= nil)
  ok("the shadowed object is the rotable", rot ~= nil and rawget(rot, "setNewSmsCb") == nil)
  ok("the rotable refuses writes (as on firmware)", not pcall(function() rot.setNewSmsCb = nil end))
  ok("sms.send still reaches the library through the proxy", type(sms.send) == "function" and rawget(sms, "send") == nil)
end
eq("register url", find("/api/register")[1].url, BASE .. "/api/register?dev=" .. dev())
eq("register bearer", find("/api/register")[1].headers["Authorization"], "Bearer " .. secret)
eq("register blob (all keys, boot=1, ota=-)", gcm.open(key1raw, find("/api/register")[1].body), reg_json("SIM 1 · 中国电信", "", "-", 1))
eq("poll url", find("/api/poll?")[1].url, BASE .. "/api/poll?dev=" .. dev())
eq("poll bearer", find("/api/poll?")[1].headers["Authorization"], "Bearer " .. secret)
eq("gw sees pending", require("gw")._state().trust, "pending")
requests = {}
fake.sms_incoming("10086", "您的验证码 1234")
fake.tick(20000)
eq("pending: queued, not uploaded", #require("gw")._state().queue .. " " .. #find(UPLOAD_PATH), "1 0")
eq("#status while pending", sms_reply(OWNER, "#status"), "2.0.0 csq=20 net=1 ip=10.0.0.2 q=1 gcm=ok fw=V2050 trust=pending ota=- boot=1")
status = "trusted"
next_poll(); fake.tick(100)
eq("trusted: upload", #find(UPLOAD_PATH), 1)
eq("upload bearer is the device secret", find(UPLOAD_PATH)[1].headers["Authorization"], "Bearer " .. secret)
eq("upload decrypts under the config key", gcm.open(key1raw, find(UPLOAD_PATH)[1].body), inbound("10086", "您的验证码 1234"))
-- Health: alive (polls answered) → boot_fail cleared once 5 min are up, not before.
eq("boot_fail still 1 before 5 min", fskv.get("boot_fail"), 1)
fake.tick(300000)
eq("boot_fail 0 after 5 min alive", fskv.get("boot_fail"), 0)
ok("not rebooted", not fake.rebooted)
-- Stranger "#" commands are ordinary messages; the owner's are not forwarded.
requests = {}
eq("stranger #reboot gets no reply", sms_reply(STRANGER, "#reboot"), nil)
fake.tick(100)
eq("stranger #reboot forwarded as a normal SMS", #find(UPLOAD_PATH), 1)
ok("stranger #reboot did not reboot", not fake.rebooted)
eq("#status line", sms_reply(OWNER, "#status"), "2.0.0 csq=20 net=1 ip=10.0.0.2 q=0 gcm=ok fw=V2050 trust=trusted ota=- boot=0")
-- Neither parser accepts a leading space, so " #ota clear" is an ordinary message:
-- it must be forwarded, never quietly swallowed by main.lua's interception.
requests = {}
eq("leading-space #ota clear: no reply", sms_reply(OWNER, " #ota clear"), nil)
fake.tick(20000)
eq("leading-space #ota clear is forwarded like any other SMS", #find(UPLOAD_PATH), 1)
eq("leading-space #ota clear decrypts as the original text", gcm.open(key1raw, find(UPLOAD_PATH)[1].body), inbound(OWNER, " #ota clear"))

-- =============================================================================
print("== 2. web reboot cmd: ack before reboot, dedupe across a reboot")
fskv.set("boot_fail", 2)
local ackb, id1 = web_cmd('"type":"reboot"')
eq("reboot acked ok", ackb, '{"id":' .. id1 .. ',"ok":true,"detail":"rebooting"}')
eq("ack bearer", last("/api/cmd/ack").headers["Authorization"], "Bearer " .. secret)
eq("deliberate reboot resets boot_fail", fskv.get("boot_fail"), 0)
ok("acked, not yet rebooted", not fake.rebooted)
fake.tick(5000)
ok("rebooted after 5 s", fake.rebooted)
eq("last_cmd persisted", fskv.get("last_cmd"), id1)
eq("last_cmd_res persisted", fskv.get("last_cmd_res"), "ok:rebooting")
cmd = '{"id":' .. id1 .. ',"type":"reboot"}'   -- the Worker never got the ack: same cmd again after the reboot
boot()
fake.tick(10)
eq("boot after the reboot: boot_fail 1", fskv.get("boot_fail"), 1)
eq("re-served cmd re-acked from fskv", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":' .. id1 .. ',"ok":true,"detail":"rebooting"}')
ok("dedupe logged", log_has("cmd #" .. id1 .. " already ran"))
fake.tick(20000)
ok("not re-run: no second reboot", not fake.rebooted)
eq("boot_fail not touched by the re-ack", fskv.get("boot_fail"), 1)
cmd = "null"
-- A poll-delivered `bases` moves the module to another server for good, so it must carry an
-- HMAC-SHA256 over "bases\n" .. the value under SMS_KEY — the key the Worker never holds, the
-- same construction as the OTA "<name>\n<bytes>". Signed over the value AS SENT.
local function bases_mac(v) return crypto.hmac_sha256("bases\n" .. v, key1raw) end
local function bases_cmd(v, hmac)
  return web_cmd('"type":"bases","value":"' .. v .. '"' .. (hmac and (',"hmac":"' .. hmac .. '"') or ""))
end
local BADV = "https://h.test/?a=1"
local ackf = bases_cmd(BADV, bases_mac(BADV))
ok("bad bases acked failed", ackf:match('"ok":false,"detail":"bad bases"}$') ~= nil)
eq("failed cmd also deduped", fskv.get("last_cmd_res"), "fail:bad bases")
-- No signature / a wrong one / a good signature over a different value: all refused with "hmac",
-- and nothing is written — an on-path attacker or a compromised Worker cannot capture the module.
local GOODV = "https://signed.test"
ok("bases with no hmac acked hmac", (bases_cmd(GOODV, nil)):match('"ok":false,"detail":"hmac"}$') ~= nil)
eq("unsigned bases stored nothing", fskv.get("bases"), nil)
ok("bases with a wrong hmac acked hmac", (bases_cmd(GOODV, ("0"):rep(64))):match('"ok":false,"detail":"hmac"}$') ~= nil)
eq("wrong-hmac bases stored nothing", fskv.get("bases"), nil)
ok("bases whose value was swapped under a good signature acked hmac",
  (bases_cmd("https://evil.test", bases_mac(GOODV))):match('"ok":false,"detail":"hmac"}$') ~= nil)
eq("swapped-value bases stored nothing", fskv.get("bases"), nil)
ok("unknown type acked failed", (web_cmd('"type":"format"')):match('"ok":false,"detail":"bad type"}$') ~= nil)
-- The signed one applies and reboots, exactly as before the signature existed.
ok("correctly signed bases applied", (bases_cmd(GOODV, bases_mac(GOODV))):match('"ok":true,"detail":"rebooting"}$') ~= nil)
eq("signed bases stored", fskv.get("bases"), GOODV)
ok("signed bases: acked, not yet rebooted", not fake.rebooted)
fake.tick(5000)
ok("signed bases rebooted", fake.rebooted)
fskv.del("bases")

-- =============================================================================
print("== 3. web ota cmd: install, wdt before the chunk, broken copies removed")
boot()
fake.tick(10)
local src = assert(read_file(REPO .. "/gw.lua"))
local mod = ("_G.WDT_AT_LOAD = _G.WDT_INIT_CALLS\n" .. src):gsub("\nreturn M%s*$", '\n_G.GW_TAG = "ota"\nreturn M\n')
ok("modified gw.lua differs", mod ~= src and #mod > #src)
ota_files.gw = mod
local mac = ota_mac("gw", mod)
ok("hmac is 64 lowercase hex", mac:match("^[0-9a-f]+$") ~= nil and #mac == 64)
do -- byte-exactness: fake (openssl) vs Node createHmac vs test/ota-sign.sh, all over "<name>\n<body>"
  local tmp = os.tmpname(); write_file(tmp, mod)
  local node = run("node -e 'const c=require(\"crypto\"),f=require(\"fs\");process.stdout.write(c.createHmac(\"sha256\",Buffer.from(process.argv[1],\"hex\")).update(\"gw\\n\").update(f.readFileSync(process.argv[2])).digest(\"hex\"))' " .. KEY1 .. " '" .. tmp .. "'")
  eq("fake hmac == node createHmac", mac, node)
  os.remove(tmp)
  local keyf = os.tmpname(); write_file(keyf, KEY1 .. "\n")
  local line = run("SMS_KEY_FILE='" .. keyf .. "' bash '" .. REPO .. "/test/ota-sign.sh' gw 2>/dev/null")
  eq("ota-sign.sh prints the exact SMS line", line, "#ota gw " .. ota_mac("gw", src) .. "\n")
  os.remove(keyf)
end
local function ota_ack(name, hmac) local a, id = web_cmd('"type":"ota","name":"' .. name .. '","hmac":"' .. hmac .. '"'); return (a or ""):gsub('^{"id":' .. id .. ',', "{") end
eq("wrong hmac", ota_ack("gw", ("0"):rep(64)), '{"ok":false,"detail":"hmac"}')
eq("wrong hmac → no file", ota_file("gw"), nil)
eq("body-only hmac (old scheme) refused", ota_ack("gw", crypto.hmac_sha256(mod, key1raw)), '{"ok":false,"detail":"hmac"}')
eq("gw's signature does not install it as gcm", ota_ack("gcm", mac), '{"ok":false,"detail":"http 404"}')   -- gcm is not staged
ota_files.gcm = mod
eq("gw's signature, staged as gcm → hmac", ota_ack("gcm", mac), '{"ok":false,"detail":"hmac"}')
eq("cross-name → no file", ota_file("gcm"), nil)
ota_files.gcm = "this is not lua ("
eq("broken body, right hmac", ota_ack("gcm", ota_mac("gcm", ota_files.gcm)), '{"ok":false,"detail":"compile"}')
eq("compile failure → no file", ota_file("gcm"), nil)
ota_files.gcm = ""
eq("empty body", ota_ack("gcm", ota_mac("gcm", "")), '{"ok":false,"detail":"size"}')
ota_files.gcm = nil
eq("bad name", ota_ack("foo", mac), '{"ok":false,"detail":"name"}')
do -- a write that lands short (flash full): detected by the read-back, nothing left behind
  local sandboxed_open = io.open
  io.open = function(p, m)
    local f = sandboxed_open(p, m)
    if f and m == "wb" and p:find("/ota_", 1, true) then
      return { write = function(_, d) return f:write(d:sub(1, #d // 2)) end, close = function() return f:close() end }
    end
    return f
  end
  eq("short write → write", ota_ack("gw", mac), '{"ok":false,"detail":"write"}')
  eq("short write → no file left", ota_file("gw"), nil)
  io.open = sandboxed_open
end
do -- fskv cannot clear a stuck counter: the install would be reverted at boot, so it is refused
  fskv.set("boot_fail", 3)
  local real_set, real_del = fskv.set, fskv.del
  fskv.set = function() return false end
  fskv.del = function() return false end
  eq("counter stuck ≥3 → fskv", ota_ack("gw", mac), '{"ok":false,"detail":"fskv"}')
  eq("stuck counter → no file left", ota_file("gw"), nil)
  fskv.set, fskv.del = real_set, real_del
  fskv.set("boot_fail", 1)
end
eq("good install (uppercase hmac accepted)", ota_ack("gw", mac:upper()), '{"ok":true,"detail":"' .. #mod .. '"}')
eq("/ota_gw.lua written byte-exact", ota_file("gw"), mod)
eq("gw_ota.active", _G.gw_ota.active(), "gw")
eq("install resets boot_fail", fskv.get("boot_fail"), 0)
ok("acked, not rebooted yet", not fake.rebooted)
fake.tick(10000)
ok("rebooted after 10 s", fake.rebooted)
local real_wdt_init = wdt.init
wdt.init = function(...) _G.WDT_INIT_CALLS = (_G.WDT_INIT_CALLS or 0) + 1; return real_wdt_init(...) end
_G.WDT_INIT_CALLS, _G.WDT_AT_LOAD = 0, nil
boot()
fake.tick(10)
eq("OTA gw loaded (tag visible)", _G.GW_TAG, "ota")
ok("ota load logged", log_has("ota gw loaded"))
eq("wdt armed before the OTA chunk ran", _G.WDT_AT_LOAD, 1)
eq("gw.lua did not arm a second watchdog", _G.WDT_INIT_CALLS, 1)
wdt.init = real_wdt_init
ok("OTA gw registers + polls", #find("/api/register") == 1 and polls() >= 1)
eq("register reports ota=gw, boot=1", gcm.open(key1raw, find("/api/register")[1].body), reg_json("SIM 1 · 中国电信", "", "gw", 1))
eq("#status shows ota=gw", sms_reply(OWNER, "#status"), "2.0.0 csq=20 net=1 ip=10.0.0.2 q=0 gcm=ok fw=V2050 trust=trusted ota=gw boot=1")
-- Broken copies (power loss mid-write) are removed at boot instead of lingering
-- behind a misleading ota=gw. (5 min of answered polls between boots, so the
-- boot-loop guard stays out of the picture.)
fake.tick(310000)
write_file(fake.fs_root .. "/ota_gw.lua", mod:sub(1, #mod // 2))
boot()
fake.tick(10)
ok("truncated copy: removal logged", log_has("ota gw unusable, removed"))
eq("truncated copy removed", ota_file("gw"), nil)
eq("flashed gw runs", _G.GW_TAG, nil)
ok("flashed gw polls", polls() >= 1)
eq("#status no longer claims ota=gw", sms_reply(OWNER, "#status"), "2.0.0 csq=20 net=1 ip=10.0.0.2 q=0 gcm=ok fw=V2050 trust=trusted ota=- boot=1")
fake.tick(310000)
write_file(fake.fs_root .. "/ota_gcm.lua", "local x = 1\n")   -- compiles, returns nothing
boot()
fake.tick(10)
ok("copy returning no module: removal logged", log_has("ota gcm unusable, removed"))
eq("it is removed", ota_file("gcm"), nil)
eq("flashed gcm in use", sms_reply(OWNER, "#status"), "2.0.0 csq=20 net=1 ip=10.0.0.2 q=0 gcm=ok fw=V2050 trust=trusted ota=- boot=1")

-- =============================================================================
print("== 4. OTA gw that crashes in start → reverted after 3 failed boots")
local bad = src:gsub("function M%.start%(c%)\n", "function M.start(c)\n  error('ota boom')\n", 1)
ok("crashing gw.lua differs", bad ~= src)
ota_files.gw = bad
eq("crashing OTA installs fine (it compiles)", ota_ack("gw", ota_mac("gw", bad)), '{"ok":true,"detail":"' .. #bad .. '"}')
fake.tick(10000)
for cycle = 1, 2 do
  boot()
  eq("failed boot " .. cycle .. " counted", fskv.get("boot_fail"), cycle)
  fake.tick(100)
  eq("boot " .. cycle .. ": nothing polls", polls(), 0)
  ok("boot " .. cycle .. ": start failure logged", log_has("gw start failed"))
  ok("boot " .. cycle .. ": not rebooted before 5 s", not fake.rebooted)
  fake.tick(5000)
  ok("boot " .. cycle .. ": rebooted after 5 s", fake.rebooted)
end
boot()
ok("third boot: revert logged", log_has("ota reverted"))
eq("third boot: /ota_gw.lua removed", ota_file("gw"), nil)
eq("third boot: boot_fail reset", fskv.get("boot_fail"), 0)
eq("third boot: ota inactive", _G.gw_ota.active(), "-")
fake.tick(10)
ok("third boot: flashed gw polls", polls() >= 1)
eq("third boot: flashed gw, no tag", _G.GW_TAG, nil)
fake.tick(5000)
ok("third boot: stays up", not fake.rebooted)

-- =============================================================================
print("== 5. liveness: OTA gw that never reaches the Worker vs flashed gw offline")
local silent = "local M = {}\nfunction M.start() end\nreturn M\n"   -- boots fine, never polls
ota_files.gw = silent
fake.tick(310000)
eq("silent OTA gw installs", ota_ack("gw", ota_mac("gw", silent)), '{"ok":true,"detail":"' .. #silent .. '"}')
fake.tick(10000)
for cycle = 1, 2 do
  boot()
  eq("silent boot " .. cycle .. ": counted", fskv.get("boot_fail"), cycle)
  fake.tick(14 * 60000 + 59000)
  eq("silent boot " .. cycle .. ": no polls", polls(), 0)
  ok("silent boot " .. cycle .. ": not rebooted before 15 min", not fake.rebooted)
  eq("silent boot " .. cycle .. ": counter not cleared (never alive)", fskv.get("boot_fail"), cycle)
  fake.tick(31000)
  ok("silent boot " .. cycle .. ": rebooted at 15 min", fake.rebooted)
  ok("silent boot " .. cycle .. ": failed-boot logged", log_has("no poll answered in 15 min"))
end
boot()
ok("third silent boot: reverted", log_has("ota reverted") and ota_file("gw") == nil)
fake.tick(10)
ok("flashed gw back and polling", polls() >= 1 and _G.GW_TAG == nil)
-- Flashed code, network down: main.lua must not reboot-loop a healthy device, and
-- gw.lua's own 20-failed-polls reboot must not be counted as a FAILED boot either —
-- three of those in a row would drop a healthy module into rescue mode, where every
-- inbound SMS is dropped on the floor.
fake.tick(310000)
offline = true
boot()
fake.tick(9 * 60000)   -- gw.lua's own 20-failed-polls reboot comes at ~10 min
ok("real gw offline 9 min: not rebooted", not fake.rebooted)
eq("offline: boot_fail stays 1 (never alive)", fskv.get("boot_fail"), 1)
fake.tick(3 * 60000)
ok("offline: gw.lua reboots after 20 failed polls", fake.rebooted)
ok("offline: poll-failure reboot logged", log_has("times in a row; rebooting"))
eq("flashed gw: that reboot is NOT a failed boot", fskv.get("boot_fail"), 0)
fake.log_lines = {}
for cycle = 1, 4 do
  boot()
  fake.sms_incoming("10086", "offline " .. cycle)
  fake.tick(12 * 60000)
  ok("offline cycle " .. cycle .. ": rebooted by gw.lua", fake.rebooted)
  eq("offline cycle " .. cycle .. ": counter cleared again", fskv.get("boot_fail"), 0)
  ok("offline cycle " .. cycle .. ": never enters rescue", not log_has("RESCUE MODE"))
  ok("offline cycle " .. cycle .. ": the SMS is queued, not lost", (fskv.get("qidx") or ""):find("%d") ~= nil)
end
-- The OTA half of the same rule: a copy that boots but can never reach the Worker
-- must still accumulate failed boots and be reverted.
offline = false
boot()
fake.tick(310000)
eq("online again: counter cleared", fskv.get("boot_fail"), 0)
ota_files.gw = mod
eq("real OTA gw installs", ota_ack("gw", mac), '{"ok":true,"detail":"' .. #mod .. '"}')
fake.tick(10000)
offline = true
for cycle = 1, 2 do
  boot()
  fake.tick(12 * 60000)
  eq("OTA gw offline boot " .. cycle .. ": counted as a failed boot", fskv.get("boot_fail"), cycle)
  ok("OTA gw offline boot " .. cycle .. ": rebooted", fake.rebooted)
end
boot()
ok("OTA gw that can never reach the Worker is reverted", log_has("ota reverted") and ota_file("gw") == nil)
eq("after the revert the counter is clear", fskv.get("boot_fail"), 0)
offline = false
boot(); fake.tick(310000)   -- healthy flashed boot again: counter back to 0
eq("reverted + online: counter cleared", fskv.get("boot_fail"), 0)
offline = true
boot()                      -- boot_fail 1, where the offline walk-through left off
package.preload["gw"] = function() return { start = function() end } end   -- a gw that never polls at all
boot()
fake.log_lines = {}
fake.tick(3600000)
ok("flashed gw offline for an hour: never rebooted by main.lua", not fake.rebooted)
eq("offline hour: boot_fail counted this boot (2) and nothing else", fskv.get("boot_fail"), 2)
ok("offline hour: no failed-boot log", not log_has("no poll answered"))
package.preload["gw"] = nil
offline = false

-- =============================================================================
print("== 6. flashed gw that crashes → rescue mode: registers, polls, takes commands")
package.preload["gw"] = function() return { start = function() error("flashed boom") end } end
local function crash_boots(n) for _ = 1, n do boot(); fake.tick(5000); assert(fake.rebooted, "expected a crash reboot") end end
fskv.set("boot_fail", 0)
crash_boots(2)
status = "trusted"
boot()
eq("rescue: boot_fail 3", fskv.get("boot_fail"), 3)
ok("rescue logged", log_has("RESCUE MODE"))
fake.tick(35000)   -- IP_READY wait (30 s in the fake) then register + first poll
eq("rescue: registered once", #find("/api/register"), 1)
eq("rescue: register bearer", find("/api/register")[1].headers["Authorization"], "Bearer " .. secret)
eq("rescue: register blob shows boot=3, ota=-", gcm.open(key1raw, find("/api/register")[1].body), reg_json("SIM 1", "", "-", 3))
eq("rescue: first poll", polls(), 1)
fake.tick(120000)
eq("rescue: polls every 60 s", polls(), 3)
eq("rescue: no uploads, no outbox", #find(UPLOAD_PATH) + #find("/api/outbox"), 0)
fake.sms_incoming(STRANGER, "#status")
fake.sms_incoming("10086", "ignored in rescue")
fake.tick(100)
eq("rescue: stranger #status ignored, SMS not forwarded", #fake.sms_sent .. " " .. #find(UPLOAD_PATH), "0 0")
eq("rescue: owner #status", sms_reply(OWNER, "#status"), "RESCUE boot_fail=3 ota=- fw=V2050 ver=2.0.0 dev=" .. dev())
fake.tick(150000)   -- 5 min up, polls answered → retry a normal boot
ok("rescue: retries a normal boot after 5 min with answered polls", fake.rebooted)
ok("rescue: retry logged", log_has("rescue: retrying a normal boot"))
eq("rescue: counter cleared for that retry", fskv.get("boot_fail"), 0)
crash_boots(2)
boot()
eq("rescue again (3)", fskv.get("boot_fail"), 3)
-- Web OTA repair from rescue mode: the poll carries the ota cmd, main.lua installs, acks, reboots.
ota_files.gw = mod
cmd_id = cmd_id + 1
cmd = '{"id":' .. cmd_id .. ',"type":"ota","name":"gw","hmac":"' .. mac .. '"}'
fake.tick(35000)
eq("rescue: ota cmd acked ok", last("/api/cmd/ack") and last("/api/cmd/ack").body, '{"id":' .. cmd_id .. ',"ok":true,"detail":"' .. #mod .. '"}')
eq("rescue: ota file written", ota_file("gw"), mod)
eq("rescue: install cleared boot_fail", fskv.get("boot_fail"), 0)
ok("rescue: not yet rebooted", not fake.rebooted)
fake.tick(10000)
ok("rescue: rebooted 10 s after the ack", fake.rebooted)
cmd = "null"
boot()
fake.tick(10)
eq("repaired: OTA gw runs although the flashed gw is broken", _G.GW_TAG, "ota")
ok("repaired: registers + polls", #find("/api/register") == 1 and polls() >= 1)
eq("repaired: boot_fail 1", fskv.get("boot_fail"), 1)
-- Pending device in rescue: the poll's cmd is ignored (there is none); loop keeps going.
fake.tick(310000)
fake.fs_clear()
crash_boots(2)
status = "pending"
boot()
fake.tick(35000 + 120000)
ok("rescue while pending: polls answered, nothing run", polls() >= 3 and #find("/api/cmd/ack") == 0)
-- Rescue with no network: retry after 15 min regardless.
offline = true
fake.sms_sent = {}
sms_reply(OWNER, "#reboot")
ok("rescue: #reboot", fake.rebooted)
eq("rescue: #reboot is deliberate, counter cleared", fskv.get("boot_fail"), 0)
crash_boots(2)
boot()
eq("rescue offline: 3", fskv.get("boot_fail"), 3)
fake.tick(14 * 60000 + 59000)
ok("rescue offline: still up before 15 min", not fake.rebooted)
ok("rescue offline: polls failing", log_has("rescue: poll failed"))
fake.tick(31000)
ok("rescue offline: retries a normal boot after 15 min", fake.rebooted)
eq("rescue offline: counter cleared for that retry", fskv.get("boot_fail"), 0)
offline = false
status = "trusted"
-- An error inside the rescue poll must not stop the loop (everything is pcall'd twice over;
-- gw_alive is the one unguarded call in the poll, so make it throw).
crash_boots(2)
boot()
local real_alive = _G.gw_alive
_G.gw_alive = function() error("alive boom") end
fake.tick(35000)
ok("rescue: poll error logged", log_has("rescue: poll error"))
_G.gw_alive = real_alive
requests = {}
fake.tick(60000)
ok("rescue: loop survived the error and polled again", polls() >= 1)
-- OWNER SMS in rescue: #url (bases via gw_cmd), #ota clear, #ota gw <hmac> from the config base.
eq("rescue: #url stores the bases", sms_reply(OWNER, "#url https://c.test"), "url ok rebooting")
eq("rescue: #url stored", fskv.get("bases"), "https://c.test")
fake.tick(5000)
ok("rescue: #url rebooted", fake.rebooted)
fskv.del("bases")
crash_boots(2)
boot()
eq("rescue: #ota clear reply", sms_reply(OWNER, "#ota clear"), "ota cleared rebooting")
eq("rescue: #ota clear resets boot_fail", fskv.get("boot_fail"), 0)
fake.tick(10000)
ok("rescue: #ota clear reboots", fake.rebooted)
crash_boots(2)
boot()
eq("rescue once more", fskv.get("boot_fail"), 3)
eq("rescue: #ota gw <hmac> downloads from the Worker and installs", sms_reply(OWNER, "#ota gw " .. mac), "ota ok gw " .. #mod .. " rebooting")
eq("rescue: #ota download url", last("/api/ota/get") and last("/api/ota/get").url, BASE .. "/api/ota/get?dev=" .. dev() .. "&name=gw")
fake.tick(10000)
boot()
fake.tick(10)
eq("repaired by SMS: OTA gw runs", _G.GW_TAG, "ota")
do -- fskv.get raising must not kill main.lua before the SMS handler exists
  fake.fs_clear()   -- back to the flashed (crashing) gw, so main.lua's own handler answers
  local real_get = fskv.get
  fskv.get = function() error("flash read error") end
  local bok, berr = pcall(boot)
  ok("boot survives fskv.get raising", bok, berr)
  ok("main.lua's handler is up: owner #status answered", (sms_reply(OWNER, "#status") or ""):match("^RESCUE boot_fail=") ~= nil)
  fskv.get = real_get
end
package.preload["gw"] = nil

-- =============================================================================
print("== 7. degraded hardware: TRNG failure, fskv that cannot keep the identity")
offline = false
status = "trusted"
do -- crypto.trng returns NOTHING on failure; indexing it would throw before sys.run()
  local real_trng = crypto.trng
  crypto.trng = function() return end
  fskv.clear(); fake.fs_clear()
  local bok, berr = pcall(boot)
  ok("boot survives a TRNG failure", bok, berr)
  ok("TRNG failure logged", log_has("TRNG unavailable"))
  eq("no half-minted identity persisted", fskv.get("dev_id"), nil)
  fake.tick(60000)
  eq("no identity → nothing on the network", #requests, 0)
  ok("gw says so instead of crashing", log_has("no device identity"))
  ok("main.lua still up: owner #status answered", (sms_reply(OWNER, "#status") or ""):match("^2%.0%.0 csq=") ~= nil)
  crypto.trng = real_trng
end
do -- fskv cannot keep the identity (worn flash): main.lua hands it over in RAM
  fskv.clear(); fake.fs_clear()
  local real_set = fskv.set
  fskv.set = function(k, v) if k == "dev_id" or k == "dev_secret" then return false end; return real_set(k, v) end
  boot()
  fake.tick(10)
  fskv.set = real_set
  eq("identity did not reach fskv", fskv.get("dev_id"), nil)
  ok("gw fell back to main.lua's in-RAM identity", log_has("using main.lua's in-RAM copy"))
  eq("it still registers (a pending card appears)", #find("/api/register"), 1)
  ok("it still polls", polls() >= 1)
  local id = find("/api/register")[1].url:match("dev=([0-9a-f]+)")
  ok("register carries a 16-hex dev id", id ~= nil and #id == 16)
  eq("register bearer present", find("/api/register")[1].headers["Authorization"]:match("^Bearer [0-9a-f]+$") ~= nil, true)
end
do -- boot counter that can be neither written nor erased: rescue must not loop
  fskv.clear(); fake.fs_clear()
  package.preload["gw"] = function() return { start = function() error("flashed boom") end } end
  fskv.set("boot_fail", 0)
  crash_boots(2)
  boot()
  eq("rescue entered", fskv.get("boot_fail"), 3)
  local real_set, real_del = fskv.set, fskv.del
  fskv.set = function() return false end
  fskv.del = function() return false end
  fake.tick(35000 + 300000)
  ok("rescue: no reboot when the counter cannot be cleared", not fake.rebooted)
  ok("rescue: the stuck counter is logged", log_has("cannot clear boot_fail"))
  requests = {}
  fake.tick(15 * 60000)
  ok("rescue: still no reboot loop", not fake.rebooted)
  ok("rescue: still reachable (polls keep going)", polls() >= 10)
  fskv.set, fskv.del = real_set, real_del
  fake.tick(300000)
  ok("rescue: leaves as soon as the flash recovers", fake.rebooted)
  eq("rescue: counter cleared on the way out", fskv.get("boot_fail"), 0)
  package.preload["gw"] = nil
end

fake.fs_destroy()
print(string.format("\n%d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
