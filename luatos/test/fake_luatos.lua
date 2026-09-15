-- fake_luatos.lua — just enough of the LuatOS runtime to run gw.lua under stock
-- Lua 5.4 for unit and end-to-end tests. Time is virtual (fake.now, ms) so a
-- 30 s poll loop runs instantly; only curl-backed HTTP is real time.
--
--   local fake = require("fake_luatos")
--   fake.sms_incoming(num, txt, metas)   -- fire the sms.setNewSmsCb callback (+ SMS_INC)
--   fake.call_incoming(num)              -- CC_IND "INCOMINGCALL" with cc.lastNum() = num
--   fake.call_end()                      -- CC_IND "DISCONNECTED"
--   fake.tick(ms)                        -- run the scheduler for ms of virtual time
--   fake.STOP = true                     -- makes sys.run()/tick return
--   fake.http_mock = function(method, url, headers, body, opts) return code, hdrs, body end
--   fake.sms_mode = "ok" | "fail" | "timeout" | "report_fail" | "busy_once"
--   fake.sms_sent = { {to=, body=}, ... }   fake.http_log = { {method=,url=,headers=,body=,code=,resp=}, ... }
--
-- Booting through main.lua (test_main.lua, e2e_driver.lua):
--   fake.no_run = true                   -- sys.run() returns instead of running the scheduler
--   fake.no_config = true                -- require("config") throws, like a device with no config.lua
--   fake.config = { SMS_KEY = … }        -- served as config.lua by require (wins over no_config)
--   fake.reboot_cycle()                  -- "power cycle": clears tasks/timers/subs/callbacks and the
--                                        --   gw/gcm module cache, keeps fskv + the /ota_ sandbox,
--                                        --   re-runs main.lua via dofile
--   rtos.reboot() sets fake.rebooted and STOPs the scheduler until the next reboot_cycle.
--   io.open / os.remove on "/ota_*" paths are redirected into fake.fs_root (a mktemp dir);
--   fake.fs_clear() removes the sandboxed OTA files, fake.fs_destroy() the directory.
--
-- Crypto/base64/hex come from fake_crypto.lua (written next to this file) when
-- present; otherwise an equivalent fallback below is used.

local fake = { now = 0, STOP = false, rebooted = false, quiet = false,
               sms_sent = {}, http_log = {}, sms_mode = "ok", last_num = "13800138000",
               imsi = "460110123456789", max_steps = 200000,
               no_run = false, no_config = false, boots = 0 }
_G.fake = fake

-- Make luatos/ and luatos/test/ requirable regardless of the caller's cwd.
local here = debug.getinfo(1, "S").source:match("^@(.*)/[^/]*$") or "."
package.path = here .. "/?.lua;" .. here .. "/../?.lua;" .. package.path
fake.main_path = here .. "/../main.lua"

-- ---- writable-FS sandbox: "/ota_*" → fake.fs_root/ota_* ----------------------
-- main.lua writes OTA scripts to the device's root FS; on the desktop those
-- paths land in a throwaway directory. Every other path is untouched.
local real_open, real_remove = io.open, os.remove
local fs_made = false
local function fs_root()   -- created lazily: tests that never touch /ota_ leave no directory behind
  if not fake.fs_root then
    local p = assert(io.popen("mktemp -d '" .. (os.getenv("TMPDIR") or "/tmp") .. "/sms-fakefs.XXXXXX'", "r"))
    fake.fs_root = p:read("l"); p:close()
    assert(fake.fs_root and #fake.fs_root > 0, "mktemp -d failed")
    fs_made = true
  end
  return fake.fs_root
end
fake.fs_root = os.getenv("FAKE_FS_ROOT")   -- e2e.sh points this into its own throwaway dir
local function fs_map(path)
  if type(path) == "string" and path:sub(1, 5) == "/ota_" then return fs_root() .. path end
  return path
end
io.open = function(path, mode) return real_open(fs_map(path), mode) end
os.remove = function(path) return real_remove(fs_map(path)) end
function fake.fs_clear()
  for _, n in ipairs({ "gw", "gcm" }) do real_remove(fs_root() .. "/ota_" .. n .. ".lua") end
end
function fake.fs_destroy()
  if not fake.fs_root then return end
  fake.fs_clear()
  if fs_made then os.execute("rmdir '" .. fake.fs_root .. "' 2>/dev/null") end
end

-- ---- log (defined before fake_crypto so its fallback does not win) --------
local function fmt(...)
  local t = {}
  for i = 1, select("#", ...) do t[i] = tostring((select(i, ...))) end
  return table.concat(t, " ")
end
log = {}
fake.log_lines = {}
local function mklog(level)
  return function(...)
    local line = string.format("[%s] %s", level, fmt(...))
    fake.log_lines[#fake.log_lines + 1] = line
    if not fake.quiet then io.stderr:write(line, "\n") end
  end
end
log.info, log.warn, log.error, log.debug = mklog("I"), mklog("W"), mklog("E"), mklog("D")

-- ---- crypto / string extensions -------------------------------------------
local have_fc = pcall(require, "fake_crypto")
if not have_fc then
  crypto = crypto or {}
  local seq = 0
  local function tmp(n) return os.tmpname() .. "_" .. n end
  crypto.cipher_encrypt = crypto.cipher_encrypt or function(typ, pad, str, key)
    assert(typ == "AES-256-ECB" and pad == "NONE", "fallback crypto: only AES-256-ECB/NONE")
    if #str == 0 then return "" end
    seq = seq + 1
    local fin, fout = tmp(seq), tmp(seq + 1)
    local f = assert(io.open(fin, "wb")); f:write(str); f:close()
    local hex = (key:gsub(".", function(c) return string.format("%02x", c:byte()) end))
    assert(os.execute(string.format("openssl enc -aes-256-ecb -nopad -K %s -in '%s' -out '%s' 2>/dev/null", hex, fin, fout)))
    f = assert(io.open(fout, "rb")); local out = f:read("a"); f:close()
    os.remove(fin); os.remove(fout)
    return out
  end
  crypto.trng = crypto.trng or function(n)
    local f = assert(io.open("/dev/urandom", "rb")); local d = f:read(n); f:close(); return d
  end
  local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local function b64c(v) return B64:sub(v + 1, v + 1) end
  string.toBase64 = string.toBase64 or function(data)
    local out = {}
    for i = 1, #data, 3 do
      local a, b, c = data:byte(i, i + 2)
      local n = (a << 16) | ((b or 0) << 8) | (c or 0)
      out[#out + 1] = b64c(n >> 18) .. b64c((n >> 12) & 63)
        .. (b and b64c((n >> 6) & 63) or "=") .. (c and b64c(n & 63) or "=")
    end
    return table.concat(out)
  end
  local D = {}
  for i = 1, #B64 do D[B64:byte(i)] = i - 1 end
  string.fromBase64 = string.fromBase64 or function(str)
    local vals = {}
    for i = 1, #str do local v = D[str:byte(i)]; if v then vals[#vals + 1] = v end end
    local out = {}
    for i = 1, #vals, 4 do
      local a, b, c, d = vals[i], vals[i + 1], vals[i + 2], vals[i + 3]
      if not b then break end
      out[#out + 1] = string.char(((a << 2) | (b >> 4)) & 0xFF)
      if c then out[#out + 1] = string.char(((b << 4) | (c >> 2)) & 0xFF) end
      if d then out[#out + 1] = string.char(((c << 6) | d) & 0xFF) end
    end
    return table.concat(out)
  end
  string.toHex = string.toHex or function(s)
    return (s:gsub(".", function(c) return string.format("%02X", c:byte()) end)), #s
  end
  string.fromHex = string.fromHex or function(h)
    return (h:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
  end
end

-- crypto.hmac_sha256(data, key) → 64 lowercase hex chars (LuatOS returns hex;
-- main.lua lowercases both sides, so the case here is not load-bearing).
-- Byte-exactness is cross-checked against Node's createHmac in test_main.lua.
crypto.hmac_sha256 = crypto.hmac_sha256 or function(data, key)
  local hexkey = (tostring(key):gsub(".", function(c) return string.format("%02x", c:byte()) end))
  local fn = os.tmpname()
  local f = assert(io.open(fn, "wb")); f:write(data); f:close()
  local p = assert(io.popen("openssl dgst -sha256 -mac HMAC -macopt hexkey:" .. hexkey .. " -r '" .. fn .. "' 2>/dev/null", "r"))
  local out = p:read("a") or ""; p:close(); os.remove(fn)
  local mac = out:match("^(%x+)")
  assert(mac and #mac == 64, "openssl hmac failed")
  return mac:lower()
end

-- ---- sys: cooperative scheduler over virtual time --------------------------
sys = {}
package.preload["sys"] = function() return sys end
package.preload["sysplus"] = function() return {} end

local tasks, timers, subs, msgq = {}, {}, {}, {}
local timer_seq = 0

local function current_task()
  local co = coroutine.running()
  for _, t in ipairs(tasks) do if t.co == co then return t end end
  return nil
end

function sys.taskInit(fn, ...)
  local args = table.pack(...)
  local t = { ready = true }
  t.co = coroutine.create(function() return fn(table.unpack(args, 1, args.n)) end)
  tasks[#tasks + 1] = t
  return t.co
end

function sys.wait(ms)
  local t = assert(current_task(), "sys.wait called outside a sys.taskInit task")
  t.wake_at, t.topic, t.ready = fake.now + (ms or 0), nil, false
  return coroutine.yield()
end

function sys.waitUntil(topic, ms)
  local t = assert(current_task(), "sys.waitUntil called outside a sys.taskInit task")
  t.topic, t.wake_at, t.ready = topic, (ms and fake.now + ms or math.huge), false
  return coroutine.yield()
end

function sys.publish(topic, ...)
  msgq[#msgq + 1] = { topic = topic, args = table.pack(...) }
end

function sys.subscribe(topic, fn)
  subs[topic] = subs[topic] or {}
  table.insert(subs[topic], fn)
end

function sys.unsubscribe(topic, fn)
  local l = subs[topic] or {}
  for i = #l, 1, -1 do if l[i] == fn then table.remove(l, i) end end
end

local function timer_add(fn, ms, period, ...)
  timer_seq = timer_seq + 1
  timers[timer_seq] = { fn = fn, at = fake.now + ms, period = period, args = table.pack(...) }
  return timer_seq
end
function sys.timerStart(fn, ms, ...) return timer_add(fn, ms, nil, ...) end
function sys.timerLoopStart(fn, ms, ...) return timer_add(fn, ms, ms, ...) end
function sys.timerStop(id)
  if type(id) == "number" then timers[id] = nil; return end
  for k, tm in pairs(timers) do if tm.fn == id then timers[k] = nil end end
end
function sys.timerStopAll(fn) sys.timerStop(fn) end
function sys.timerIsActive(id)
  if type(id) == "number" then return timers[id] ~= nil end
  for _, tm in pairs(timers) do if tm.fn == id then return true end end
  return false
end

local function resume(t, ...)
  local ok, err = coroutine.resume(t.co, ...)
  if not ok then log.error("fake", "task error:", err); t.dead = true end
  if coroutine.status(t.co) == "dead" then t.dead = true end
end

local function snapshot(list)
  local c = {}
  for i, v in ipairs(list) do c[i] = v end
  return c
end

-- One scheduler pass at the current virtual time. Returns true if it did work.
local function step()
  local did = false
  while #msgq > 0 do
    local m = table.remove(msgq, 1)
    did = true
    for _, fn in ipairs(snapshot(subs[m.topic] or {})) do
      local ok, err = pcall(fn, table.unpack(m.args, 1, m.args.n))
      if not ok then log.error("fake", "subscriber error:", err) end
    end
    for _, t in ipairs(snapshot(tasks)) do
      if not t.dead and t.topic == m.topic then
        t.topic, t.wake_at = nil, nil
        resume(t, true, table.unpack(m.args, 1, m.args.n))
      end
    end
  end
  for _, t in ipairs(snapshot(tasks)) do
    if not t.dead and t.ready then t.ready = false; did = true; resume(t) end
  end
  for _, t in ipairs(snapshot(tasks)) do
    if not t.dead and not t.ready and t.wake_at and t.wake_at <= fake.now then
      did = true
      local was_topic = t.topic
      t.topic, t.wake_at = nil, nil
      if was_topic then resume(t, false) else resume(t) end
    end
  end
  local due = {}
  for id, tm in pairs(timers) do if tm.at <= fake.now then due[#due + 1] = id end end
  table.sort(due)
  for _, id in ipairs(due) do
    local tm = timers[id]
    if tm then
      did = true
      if tm.period then tm.at = fake.now + tm.period else timers[id] = nil end
      local ok, err = pcall(tm.fn, table.unpack(tm.args, 1, tm.args.n))
      if not ok then log.error("fake", "timer error:", err) end
    end
  end
  for i = #tasks, 1, -1 do if tasks[i].dead then table.remove(tasks, i) end end
  return did
end

local function next_event()
  local nxt
  for _, t in ipairs(tasks) do
    if not t.dead and not t.ready and t.wake_at and (not nxt or t.wake_at < nxt) then nxt = t.wake_at end
  end
  for _, tm in pairs(timers) do if not nxt or tm.at < nxt then nxt = tm.at end end
  return nxt
end

-- Run until STOP, until nothing is pending, or until virtual time reaches `limit`.
function fake.run(limit)
  local steps = 0
  while not fake.STOP do
    local did = step()
    steps = steps + 1
    if steps > fake.max_steps then error("fake_luatos: runaway scheduler loop") end
    if not did then
      local nxt = next_event()
      if not nxt or nxt == math.huge then break end
      if limit and nxt > limit then fake.now = limit; break end
      fake.now = nxt
    end
  end
end
function fake.tick(ms) fake.run(fake.now + ms) end
function sys.run() if not fake.no_run then fake.run(nil) end end
function fake.pending_tasks() return #tasks end

-- "Power cycle": everything in RAM is gone (tasks, timers, subscriptions, the
-- SMS callback, the gw/gcm module instances), fskv and the FS sandbox stay,
-- then main.lua runs again from the top. rtos.reboot() only STOPs the
-- scheduler; the test decides when the "device" comes back up.
local sms_cb
local sms_rotable   -- the read-only `sms` view built below (forward-declared for reboot_cycle)
function fake.reboot_cycle()
  fake.rebooted, fake.STOP = false, false
  tasks, timers, subs, msgq = {}, {}, {}, {}
  sms_cb = nil
  sms = sms_rotable   -- main.lua shadows the global with a proxy per boot; a fresh process starts unshadowed
  _G.WDT_ARMED = nil
  _G.gw_ident = nil   -- RAM is gone: main.lua re-mints / re-reads the identity every boot
  package.loaded["gw"], package.loaded["gcm"], package.loaded["config"] = nil, nil, nil
  if fake.config then
    package.preload["config"] = function() return fake.config end
  elseif fake.no_config then
    package.preload["config"] = function() error("module 'config' not found (fake.no_config)") end
  else
    package.preload["config"] = nil   -- a real config.lua on package.path (e2e), or none
  end
  fake.boots = fake.boots + 1
  dofile(fake.main_path)
end

-- ---- http: curl via io.popen (or fake.http_mock) ---------------------------
http = {}
local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

local function curl(method, url, headers, body, timeout)
  local outf = os.tmpname()
  local bodyf
  local cmd = { "curl", "-s", "-o", shq(outf), "-w", "'%{http_code}'", "-X", shq(method),
                "--max-time", tostring(math.max(1, math.ceil((timeout or 60000) / 1000))), "-H", "'Expect:'" }
  for k, v in pairs(headers or {}) do cmd[#cmd + 1] = "-H"; cmd[#cmd + 1] = shq(k .. ": " .. v) end
  if body then
    bodyf = os.tmpname()
    local f = assert(io.open(bodyf, "wb")); f:write(body); f:close()
    cmd[#cmd + 1] = "--data-binary"; cmd[#cmd + 1] = shq("@" .. bodyf)
  end
  cmd[#cmd + 1] = shq(url)
  local p = io.popen(table.concat(cmd, " ") .. " 2>/dev/null", "r")
  local out = p:read("a") or ""
  local _, _, status = p:close()
  local f = io.open(outf, "rb")
  local rb = f and f:read("a") or ""
  if f then f:close() end
  os.remove(outf)
  if bodyf then os.remove(bodyf) end
  local code = tonumber(out) or 0
  if code == 0 then return (status == 28) and -8 or -4, {}, "" end
  return code, {}, rb
end

function http.request(method, url, headers, body, opts, ca)
  local rec = { method = method, url = url, headers = headers or {}, body = body, opts = opts, ca = ca }
  fake.http_log[#fake.http_log + 1] = rec
  local code, rh, rb
  if fake.http_mock then
    code, rh, rb = fake.http_mock(method, url, headers or {}, body, opts)
  else
    code, rh, rb = curl(method, url, headers, body, opts and opts.timeout)
  end
  rec.code, rec.resp = code, rb
  local r = {}
  r.wait = function() return code, rh or {}, rb or "" end   -- works as r.wait() and r:wait()
  return r
end

-- ---- sms -------------------------------------------------------------------
-- On real firmware `sms` is a ROTABLE: a userdata whose metatable has __index
-- but no __newindex, so any `sms.foo = x` raises. The fake reproduces that (a
-- plain table here would hide a boot-fatal bug in main.lua), which is why
-- fake.sms is the implementation and the global is a read-only view of it.
fake.sms = {}
local sms_impl = fake.sms
sms_rotable = setmetatable({}, {
  __index = sms_impl,
  __newindex = function(_, k) error("attempt to index a rotable value (global 'sms." .. tostring(k) .. "')", 2) end,
  __metatable = false,
  __name = "rotable",
})
sms = sms_rotable
function fake.real_set_sms_cb(fn) sms_cb = fn end
sms_impl.setNewSmsCb = fake.real_set_sms_cb
function sms_impl.autoLong() return true end
function sms_impl.send(to, body)
  fake.sms_sent[#fake.sms_sent + 1] = { to = to, body = body }
  local mode = fake.sms_mode
  if mode == "fail" then return false end
  if mode == "timeout" then return true end
  if mode == "busy_once" then
    -- LuatOS returns nothing while a previous send still owes its SMS_SENT;
    -- deliver that late report shortly, then behave like "ok" for the retry.
    fake.sms_mode = "ok"
    sys.timerStart(function() sys.publish("SMS_SENT", true, 0, "ok", 1, 0, { 1 }) end, 100)
    return nil
  end
  sys.timerStart(function()
    if mode == "report_fail" then sys.publish("SMS_SENT", false, 30, "unknown subscriber", 1, 500, {})
    else sys.publish("SMS_SENT", true, 0, "ok", 1, 0, { 1 }) end
  end, 100)
  return true
end
function fake.sms_incoming(num, txt, metas)
  metas = metas or { refNum = 0, seqNum = 1, maxNum = 1, year = 2026, mon = 9, day = 15, hour = 10, min = 0, sec = 0, tz = 32 }
  if sms_cb then
    local ok, err = pcall(sms_cb, num, txt, metas)
    if not ok then log.error("fake", "sms cb error:", err) end
  end
  sys.publish("SMS_INC", num, txt, metas)
end

-- ---- fskv (in-memory, 4095-byte value limit) --------------------------------
-- Optionally file-backed (env E2E_FSKV) so a value written by one process — the
-- device id, the done-ring, a persisted queue — survives into the next `lua`
-- run, exactly as flash fskv survives a reboot. This is what lets e2e.sh drive
-- the module across separate driver invocations. Without the env it is a plain
-- in-memory bag, so the unit tests are unaffected.
-- File format: one "<b64 key>\t<type>\t<b64 payload>" per line; type s/n/b/t
-- (string, number, boolean, table serialized as a Lua literal — main.lua keeps
-- dev_id / dev_secret, the boot counter "boot_fail", the last acked web
-- command "last_cmd"/"last_cmd_res" and the "bases" override there).
fskv = { _store = {} }
local FSKV_FILE = os.getenv("E2E_FSKV")
local function lua_literal(v)
  local t = type(v)
  if t == "string" then return string.format("%q", v) end
  if t == "number" or t == "boolean" then return tostring(v) end
  if t == "table" then
    local out = {}
    for k, x in pairs(v) do out[#out + 1] = "[" .. lua_literal(k) .. "]=" .. lua_literal(x) end
    return "{" .. table.concat(out, ",") .. "}"
  end
  return "nil"
end
local function fskv_load()
  if not FSKV_FILE then return end
  local f = io.open(FSKV_FILE, "rb")
  if not f then return end
  for line in f:lines() do
    local kb, ty, vb = line:match("^([^\t]*)\t([snbt])\t(.*)$")
    if kb and #kb > 0 then
      local raw = string.fromBase64(vb)
      local v
      if ty == "s" then v = raw
      elseif ty == "n" then v = math.tointeger(tonumber(raw)) or tonumber(raw)
      elseif ty == "b" then v = (raw == "true")
      else local fn = load("return " .. raw, "=fskv", "t", {}); v = fn and fn() end
      fskv._store[string.fromBase64(kb)] = v
    end
  end
  f:close()
end
local function fskv_save()
  if not FSKV_FILE then return end
  local out = {}
  for k, v in pairs(fskv._store) do
    local ty = ({ string = "s", number = "n", boolean = "b", table = "t" })[type(v)]
    if ty then
      local payload = (ty == "t") and lua_literal(v) or tostring(v)
      out[#out + 1] = string.toBase64(k) .. "\t" .. ty .. "\t" .. string.toBase64(payload)
    end
  end
  local f = assert(io.open(FSKV_FILE, "wb"))
  f:write(table.concat(out, "\n"))
  f:close()
end
function fskv.init() fskv._inited = true; fskv_load(); return true end
function fskv.set(k, v)
  if type(k) ~= "string" or k == "" then return false end
  if v == nil or type(v) == "function" then return false end
  if type(v) == "string" and #v > 4095 then log.warn("fskv", "value too large", k, #v); return false end
  fskv._store[k] = v
  fskv_save()
  return true
end
function fskv.get(k) return fskv._store[k] end
function fskv.del(k) fskv._store[k] = nil; fskv_save(); return true end
function fskv.clear() fskv._store = {}; fskv_save(); return true end

-- ---- mobile / rtos / wdt / socket / cc -------------------------------------
mobile = {
  imsi = function() return fake.imsi end,
  imei = function() return "861234567890123" end,
  iccid = function() return "89860012345678901234" end,
  number = function() return fake.number end,   -- nil on most real SIMs; main.lua sends ""
  csq = function() return 20 end,
  status = function() return fake.net_status or 1 end,
  setAuto = function() end,
  syncTime = function() return true end,
  ipv6 = function() return false end,
  scell = function() return { mcc = 460, mnc = 11 } end,
}
rtos = {
  version = function() return "V2050" end,
  bsp = function() return "Air780EHV" end,
  buildDate = function() return "2026-08-21" end,
  reboot = function() log.warn("fake", "rtos.reboot() called"); fake.rebooted = true; fake.STOP = true end,
  meminfo = function() return 4194304, 65536, 131072 end,
}
wdt = { init = function() return true end, feed = function() return true end }
socket = {
  LWIP_GP = 1,
  setDNS = function() end,
  localIP = function() return "10.0.0.2", "255.255.255.0", "10.0.0.1" end,
  dft = function() return 1 end,
  adapter = function() return true end,
}
cc = { lastNum = function() return fake.last_num end }
function fake.call_incoming(num)
  if num then fake.last_num = num end
  sys.publish("CC_IND", "INCOMINGCALL")
end
function fake.call_end() sys.publish("CC_IND", "DISCONNECTED") end
function fake.ip_ready() sys.publish("IP_READY", "10.0.0.2", 1) end

-- ---- json: decode only (pure Lua, enough for arrays of {id,payload}) ------
json = { null = setmetatable({}, { __tostring = function() return "null" end }) }
do
  local function decode_error(str, i, msg) error(string.format("%s at position %d", msg, i), 0) end
  local function skip_ws(str, i) return (str:find("%S", i)) or (#str + 1) end
  local parse_value
  local escapes = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }
  local function utf8_char(cp)
    if cp < 0x80 then return string.char(cp)
    elseif cp < 0x800 then return string.char(0xC0 | (cp >> 6), 0x80 | (cp & 0x3F))
    elseif cp < 0x10000 then return string.char(0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F))
    else return string.char(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3F), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F)) end
  end
  local function parse_string(str, i)
    local out = {}
    i = i + 1
    while true do
      local c = str:sub(i, i)
      if c == "" then decode_error(str, i, "unterminated string") end
      if c == '"' then return table.concat(out), i + 1 end
      if c == "\\" then
        local e = str:sub(i + 1, i + 1)
        if e == "u" then
          local hex = str:sub(i + 2, i + 5)
          if not hex:match("^%x%x%x%x$") then decode_error(str, i, "bad \\u escape") end
          local cp = tonumber(hex, 16)
          i = i + 6
          if cp >= 0xD800 and cp <= 0xDBFF and str:sub(i, i + 1) == "\\u" then
            local lo = tonumber(str:sub(i + 2, i + 5), 16)
            if lo and lo >= 0xDC00 and lo <= 0xDFFF then
              cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
              i = i + 6
            end
          end
          out[#out + 1] = utf8_char(cp)
        elseif escapes[e] then
          out[#out + 1] = escapes[e]; i = i + 2
        else
          decode_error(str, i, "bad escape")
        end
      else
        out[#out + 1] = c; i = i + 1
      end
    end
  end
  local function parse_number(str, i)
    local s, e = str:find("^-?%d+%.?%d*[eE]?[-+]?%d*", i)
    if not s then decode_error(str, i, "bad number") end
    local txt = str:sub(s, e)
    local n = math.tointeger(tonumber(txt)) or tonumber(txt)
    if not n then decode_error(str, i, "bad number") end
    return n, e + 1
  end
  local function parse_array(str, i)
    local arr = {}
    i = skip_ws(str, i + 1)
    if str:sub(i, i) == "]" then return arr, i + 1 end
    while true do
      local v
      v, i = parse_value(str, i)
      arr[#arr + 1] = v
      i = skip_ws(str, i)
      local c = str:sub(i, i)
      if c == "]" then return arr, i + 1 end
      if c ~= "," then decode_error(str, i, "expected , or ]") end
      i = skip_ws(str, i + 1)
    end
  end
  local function parse_object(str, i)
    local obj = {}
    i = skip_ws(str, i + 1)
    if str:sub(i, i) == "}" then return obj, i + 1 end
    while true do
      if str:sub(i, i) ~= '"' then decode_error(str, i, "expected string key") end
      local k
      k, i = parse_string(str, i)
      i = skip_ws(str, i)
      if str:sub(i, i) ~= ":" then decode_error(str, i, "expected :") end
      i = skip_ws(str, i + 1)
      local v
      v, i = parse_value(str, i)
      obj[k] = v
      i = skip_ws(str, i)
      local c = str:sub(i, i)
      if c == "}" then return obj, i + 1 end
      if c ~= "," then decode_error(str, i, "expected , or }") end
      i = skip_ws(str, i + 1)
    end
  end
  parse_value = function(str, i)
    i = skip_ws(str, i)
    local c = str:sub(i, i)
    if c == "{" then return parse_object(str, i)
    elseif c == "[" then return parse_array(str, i)
    elseif c == '"' then return parse_string(str, i)
    elseif c == "-" or c:match("%d") then return parse_number(str, i)
    elseif str:sub(i, i + 3) == "true" then return true, i + 4
    elseif str:sub(i, i + 4) == "false" then return false, i + 5
    elseif str:sub(i, i + 3) == "null" then return json.null, i + 4
    end
    decode_error(str, i, "unexpected character '" .. c .. "'")
  end
  -- LuatOS json.decode contract: obj, 1 on success; nil, 0, err on failure.
  function json.decode(str)
    if type(str) ~= "string" then return nil, 0, "not a string" end
    local ok, v, i = pcall(parse_value, str, 1)
    if not ok then return nil, 0, v end
    if skip_ws(str, i) <= #str then return nil, 0, "trailing garbage" end
    return v, 1
  end
end

return fake
