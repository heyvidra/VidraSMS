-- gw.lua — the SMS gateway application for the Air780EHV (LuatOS).
--
-- Everything the module does lives here so main.lua stays a small, never-
-- updated boot stub (config merge, device identity, OTA of this file, the web
-- command runner, boot-loop guard live there) and the pure helpers can be
-- unit-tested under stock Lua with test/fake_luatos.lua. The inbound/outbox
-- wire formats mirror the Android app byte-for-byte (android/.../SyncWorker.kt,
-- SmsSender.kt). On top of that the module has an identity of its own: it
-- registers with the Worker (POST /api/register), is trusted or blocked on the
-- web, and polls GET /api/poll — outbox rows plus one command per round.
--
-- Layout: pure helpers first (exported on M for the tests), then the device
-- runtime (queue, uploader task, poller task, SMS/call callbacks), then M.start.
--
-- LuatOS globals used: sys, http, sms, fskv, mobile, crypto, log, rtos, json,
-- socket; optional (guarded): cc. `.wait()` calls only ever run inside
-- sys.taskInit tasks; timer callbacks never yield. From main.lua: _G.gw_reg
-- (the registration JSON), _G.gw_cmd.run (web commands), _G.gw_ota.active (OTA
-- state), _G.gw_alive (boot health) — guarded, so the helpers load standalone.
-- To main.lua: _G.gw_status_line, the rich line a signed "#status" SMS answers
-- with. SMS commands themselves are main.lua's: they must survive a broken gw.lua.

local M = {}

-- main.lua's load_module prefers an OTA copy (/ota_gcm.lua) over the flashed
-- gcm.lua; plain require when gw.lua runs standalone (unit tests).
-- Two quoted strings on one line that mentions require confuses Luatools' scanner (it reads
-- first-quote-to-last-quote as the module name), so the fallback gets its own line.
local gcm = _G.load_module and _G.load_module("gcm")
if not gcm then gcm = require("gcm") end

-- Plaintext budget. ceil((3000+28)/3)*4 + 3 = 4043 bytes on the wire, which
-- also keeps the fskv value (limit 4095) comfortable.
M.MAX_PLAIN = 3000
M.MARKER = "…[截断]"          -- U+2026 + "[截断]" = 11 UTF-8 bytes
M.RING_MAX = 40
M.QUEUE_MAX = 50
local FSKV_MAX = 4095
local OUTBOX_MAX = 4043    -- largest legitimate v1 outbox blob; reject bigger before the pure-Lua GCM decrypt
local UPLOAD_TIMEOUT = 10000
local POLL_TIMEOUT = 15000
local ACK_TIMEOUT = 15000
local SEND_WAIT = 45000
local REGISTER_EVERY_MS = 30 * 60000
local POLL_FAIL_REBOOT = 20
local PREFIX_AFTER_S = 120     -- Android: [原时间] only when uploaded ≥120 s after receipt
local CLOCK_VALID_S = 1e9      -- os.time() below this = RTC not yet NITZ-synced

-- ---------------------------------------------------------------------------
-- Pure helpers (byte-exact ports of the Android code)
-- ---------------------------------------------------------------------------

-- jsonEscape (SyncWorker.kt:158–170): only " \ \n \r \t and other C0 controls
-- (as \u00xx, lowercase). DEL and everything ≥0x80 pass through as raw UTF-8.
function M.json_escape(s)
  s = tostring(s == nil and "" or s)
  return (s:gsub('[%c"\\]', function(c)
    if c == '"' then return '\\"'
    elseif c == '\\' then return '\\\\'
    elseif c == '\n' then return '\\n'
    elseif c == '\r' then return '\\r'
    elseif c == '\t' then return '\\t'
    end
    local b = c:byte()
    if b < 0x20 then return string.format('\\u%04x', b) end
    return c  -- 0x7f: %c matches it, Android does not escape it
  end))
end

-- clampBody (SyncWorker.kt:124–133): keep ≤ limit bytes, cut on a UTF-8
-- boundary (Android decodes then strips U+FFFD; we walk back over
-- continuation bytes, which is the same thing without a decoder) and append
-- the marker. ponytail: a *literal* trailing U+FFFD in the original text is
-- kept, Android would strip it; nobody sends that.
function M.clamp_body(body, limit)
  body = tostring(body == nil and "" or body)
  if #body <= limit then return body end
  local cut = limit - #M.MARKER
  if cut < 0 then cut = 0 end
  while cut > 0 and ((body:byte(cut + 1) or 0) & 0xC0) == 0x80 do
    cut = cut - 1
  end
  return body:sub(1, cut) .. M.MARKER
end

local function blank(s) return type(s) ~= "string" or not s:match("%S") end

-- sealMessage (SyncWorker.kt:182–213) minus the encryption: the exact JSON
-- {"s":..,"b":..,"k":..,"d":..} with the same room math, so a long body is
-- truncated at the same byte as on a phone.
function M.build_inbound(sender, body, k, dev)
  local sj = M.json_escape(sender)
  local kj = (not blank(k)) and M.json_escape(k) or nil
  local dj = (not blank(dev)) and M.json_escape(dev) or nil
  local overhead = 24 + (kj and (#kj + 8) or 0) + (dj and (#dj + 8) or 0)
  local room = M.MAX_PLAIN - #sj - overhead
  if room < 64 then room = 64 end
  local bj = M.json_escape(M.clamp_body(body, room))
  while #bj > room do
    local over = #bj - room
    local nxt = M.json_escape(M.clamp_body(body, math.max(room - over, 16)))
    if nxt == bj then break end
    bj = nxt
  end
  local out = { '{"s":"', sj, '","b":"', bj, '"' }
  if kj then out[#out + 1] = ',"k":"' .. kj .. '"' end
  if dj then out[#out + 1] = ',"d":"' .. dj .. '"' end
  out[#out + 1] = "}"
  return table.concat(out)
end

-- formatBody (SyncWorker.kt:137–141), seconds instead of millis. The prefix is
-- rendered in UTC+8 because the phones run in Asia/Shanghai. Skipped while the
-- RTC is unsynced (ts < 1e9) — that is Android's `ts <= 0` branch.
function M.format_body(body, ts, now)
  if type(ts) ~= "number" or ts < CLOCK_VALID_S then return body end
  if type(now) ~= "number" or now - ts < PREFIX_AFTER_S then return body end
  local ok, t = pcall(os.date, "!%m-%d %H:%M", math.floor(ts + 8 * 3600))
  if not ok or type(t) ~= "string" then return body end
  return "[原时间 " .. t .. "]\n" .. body
end

-- PLMN → carrier keyword. The web matches "电信/移动/联通" inside the SIM label
-- (index.js matchesCarrier) and refuses to save 保号 without one, so the
-- Chinese name is functional, not cosmetic.
local CARRIERS = {
  ["46000"] = "中国移动", ["46002"] = "中国移动", ["46004"] = "中国移动",
  ["46007"] = "中国移动", ["46008"] = "中国移动",
  ["46001"] = "中国联通", ["46006"] = "中国联通", ["46009"] = "中国联通",
  ["46003"] = "中国电信", ["46005"] = "中国电信", ["46011"] = "中国电信",
  ["46012"] = "中国电信",
  ["46015"] = "中国广电",
}
function M.carrier_from_imsi(imsi)
  if type(imsi) ~= "string" then return nil end
  return CARRIERS[imsi:sub(1, 5)]
end

-- "SIM 1 · <carrier>" with the same " · " (space, U+00B7, space) as Android.
function M.sim_label(carrier)
  if blank(carrier) then return "SIM 1" end
  return "SIM 1 · " .. carrier
end

-- Ack detail (SmsSender.kt ackOutbox): success → the attempt id; failure →
-- "<CODE>｜<text> [<attempt>]" with U+FF5C FULLWIDTH VERTICAL LINE.
function M.ack_detail(code, text, attempt)
  if code == "SEND_OK" then return attempt end
  return code .. "｜" .. tostring(text == nil and "" or text) .. " [" .. tostring(attempt) .. "]"
end

-- Exactly three keys, id as an integer (the Worker 400s on anything else).
-- The same shape closes an outbox row (/api/outbox/ack) and a command (/api/cmd/ack).
function M.build_ack(id, ok, detail)
  return string.format('{"id":%d,"ok":%s,"detail":"%s"}',
    id, ok and "true" or "false", M.json_escape(detail))
end

-- Done-ring (SmsSender.kt doneRingPut/doneRingGet): "id=CODE,..." newest last,
-- oldest dropped past the cap, a re-put id moves to the end.
function M.ring_get(ring, id)
  local key = tostring(id)
  for entry in tostring(ring == nil and "" or ring):gmatch("[^,]+") do
    local k, v = entry:match("^([^=]*)=(.*)$")
    if k == key and v ~= nil and v:match("%S") then return v end
  end
  return nil
end

function M.ring_put(ring, id, code, max)
  max = max or M.RING_MAX
  local key = tostring(id)
  local out = {}
  for entry in tostring(ring == nil and "" or ring):gmatch("[^,]+") do
    if entry:match("%S") and entry:match("^([^=]*)") ~= key then out[#out + 1] = entry end
  end
  out[#out + 1] = key .. "=" .. code
  while #out > max do table.remove(out, 1) end
  return table.concat(out, ",")
end

-- GET /api/poll body → {status=, rows={ {id=int, payload=str}… }, cmd=table|nil}, or nil
-- when it is not a JSON object with a string status. Rows without an integer id are
-- skipped; a missing payload becomes "" and later fails decryption, which is acked as
-- OUTBOX_DECRYPT_FAILED like on the phone. cmd needs an id (json null is not a cmd).
function M.parse_poll(body)
  if type(body) ~= "string" or not body:match("^%s*{") then return nil end
  local ok, t = pcall(json.decode, body)
  if not ok or type(t) ~= "table" or type(t.status) ~= "string" then return nil end
  local rows = {}
  if type(t.rows) == "table" then
    for _, row in ipairs(t.rows) do
      if type(row) == "table" then
        local id = row.id
        if type(id) == "number" then id = math.tointeger(id) end  -- cjson yields floats
        if type(id) == "number" then
          rows[#rows + 1] = { id = id, payload = type(row.payload) == "string" and row.payload or "" }
        end
      end
    end
  end
  local cmd = type(t.cmd) == "table" and t.cmd.id ~= nil and t.cmd or nil
  return { status = t.status, rows = rows, cmd = cmd }
end

-- Base list from config (table or string; comma/space separated). http:// is
-- accepted for local testing; the web `bases` command and #url are validated
-- (https only) in main.lua before they ever reach fskv.
function M.parse_bases(v)
  local out = {}
  local function add(s)
    s = tostring(s == nil and "" or s):gsub("^%s+", ""):gsub("%s+$", ""):gsub("/+$", "")
    if s:match("^https?://%S+$") then out[#out + 1] = s end
  end
  if type(v) == "table" then
    for _, s in ipairs(v) do add(s) end
  elseif type(v) == "string" then
    for s in v:gmatch("[^,%s]+") do add(s) end
  end
  return out
end

-- Attempt id like Android's newAttemptId(): SMS-yyyymmdd-<8 hex>.
function M.new_attempt_id()
  local day, rnd = "00000000", "00000000"
  pcall(function() day = os.date("!%Y%m%d") end)
  pcall(function() rnd = (crypto.trng(4):toHex()):lower() end)
  return "SMS-" .. day .. "-" .. rnd
end

-- ---------------------------------------------------------------------------
-- Device runtime
-- ---------------------------------------------------------------------------

local cfg, key32, dev_id, dev_secret, bases
local queue = {}          -- {seq, v1, raw={sender,body,ts}, prefixed, tries}
local next_seq = 1
local ring = ""           -- mirror of fskv "done"
local last_send = ""      -- register "ls"
local poll_fail = 0
local polls = 0
local ringing = false
local sim_label_cache
local started = false     -- network tasks running; false = callbacks only, nothing queued
local trusted = false     -- the web has trusted this device (uploads + sends allowed)
local trust = "?"         -- last status the Worker reported: pending | trusted | blocked | ?
local serving             -- base that last answered a poll
local reg_due = true      -- register at boot, every REGISTER_EVERY_MS, and after a trust change
local reg_polls = 0

_G.GCM_OK = false         -- read by #status; false disables every upload

local function perr(tag, ok, err) if not ok then log.error("gw", tag, err) end end

-- fskv wrappers: every call pcall'd, since a flash error must not take the
-- gateway down with it.
local function kv_get(k)
  if not fskv then return nil end
  local ok, v = pcall(fskv.get, k)
  if ok then return v end
  return nil
end
local function kv_set(k, v)
  if not fskv then return false end
  local ok, r = pcall(fskv.set, k, v)
  return ok and r
end
local function kv_del(k)
  if not fskv then return false end
  local ok, r = pcall(fskv.del, k)
  return ok and r
end

local function sim_label()
  if not sim_label_cache then
    local ok, imsi = pcall(mobile.imsi)
    local carrier = ok and M.carrier_from_imsi(imsi) or nil
    if carrier then sim_label_cache = M.sim_label(carrier) end  -- imsi is nil until SIM ready: retry later
  end
  return sim_label_cache or M.sim_label(nil)
end

local function auth_headers(ctype)
  local h = { ["Authorization"] = "Bearer " .. tostring(dev_secret) }
  if ctype then h["Content-Type"] = ctype end
  return h
end

-- http.request(...).wait() → code, headers, body. Negative codes = network
-- failure (-4 connect, -8 timeout). A thrown error is mapped to -1 so callers
-- only ever branch on a number. CA_PEM, when set, goes in as the 6th
-- positional argument and turns on VERIFY_REQUIRED.
local function http_req(method, url, headers, body, timeout)
  local ok, code, hdrs, rbody = pcall(function()
    local r
    if cfg.CA_PEM then
      r = http.request(method, url, headers, body, { timeout = timeout }, cfg.CA_PEM)
    else
      r = http.request(method, url, headers, body, { timeout = timeout })
    end
    return r.wait()
  end)
  if not ok then
    log.error("gw", "http", method, url, code)
    return -1, {}, ""
  end
  if type(code) ~= "number" then code = -1 end
  return code, hdrs or {}, rbody or ""
end

-- The serving base first, then the others.
local function targets(first)
  local t = { first }
  for _, b in ipairs(bases) do if b ~= first then t[#t + 1] = b end end
  return t
end

-- POST to the serving base first, then the others; first 2xx wins.
local function post_all(first, path, ctype, body, timeout)
  for _, b in ipairs(targets(first)) do
    local code = http_req("POST", b .. path, auth_headers(ctype), body, timeout)
    if code >= 200 and code < 300 then return true, b end
  end
  return false
end

-- Wait for the cellular data link. The official demo's gate, with a fallback
-- for firmware where socket.adapter/socket.dft are missing.
local function wait_ip()
  local has = pcall(function() return socket.adapter and socket.dft end)
  if has and socket.adapter and socket.dft then
    while true do
      local ok, up = pcall(function() return socket.adapter(socket.dft()) end)
      if ok and up then return end
      sys.waitUntil("IP_READY", 1000)
    end
  else
    sys.waitUntil("IP_READY", 30000)
  end
end

-- --- outbound queue (fskv q:<seq> + qidx) ---------------------------------

local function save_idx()
  if #queue == 0 then kv_del("qidx"); return end
  local seqs = {}
  for i, it in ipairs(queue) do seqs[i] = tostring(it.seq) end
  kv_set("qidx", table.concat(seqs, ","))
end

local function load_queue()
  local idx = kv_get("qidx")
  if type(idx) ~= "string" then return end
  for s in idx:gmatch("%d+") do
    local seq = tonumber(s)
    local v1 = kv_get("q:" .. s)
    if type(v1) == "string" and v1:sub(1, 3) == "v1:" then
      queue[#queue + 1] = { seq = seq, v1 = v1, tries = 0 }   -- raw lost across reboot: no [原时间] prefix
      if seq >= next_seq then next_seq = seq + 1 end
    else
      kv_del("q:" .. s)
    end
  end
  log.info("gw", "queue restored", #queue)
end

local function seal_item(item, with_prefix)
  local raw = item.raw
  local body = raw.body
  if with_prefix then body = M.format_body(raw.body, raw.ts, os.time()) end
  local plain = M.build_inbound(raw.sender, body, sim_label(), dev_id)
  return gcm.seal(key32, plain)
end

local function dequeue(item)
  for i, it in ipairs(queue) do
    if it == item then table.remove(queue, i); break end
  end
  kv_del("q:" .. item.seq)
  save_idx()
end

local function enqueue(sender, body, ts)
  if not started then
    log.warn("gw", "network tasks not running (no key/identity/base); dropping message from", sender)
    return
  end
  if not _G.GCM_OK then
    log.error("gw", "GCM self-test failed earlier; NOT queueing message from", sender)
    return
  end
  local item = { seq = next_seq, raw = { sender = sender, body = body, ts = ts }, tries = 0 }
  next_seq = next_seq + 1
  item.v1 = seal_item(item, false)
  if #queue >= M.QUEUE_MAX then
    log.warn("gw", "queue full, dropping oldest seq", queue[1].seq)
    dequeue(queue[1])
  end
  queue[#queue + 1] = item
  if #item.v1 <= FSKV_MAX then kv_set("q:" .. item.seq, item.v1) end
  save_idx()
  log.info("gw", "queued", sender, "#bytes", #item.v1, "depth", #queue)
  sys.publish("GW_UPLOAD")
  collectgarbage()
end

-- outcomeFor (SyncWorker.kt:102–107): 2xx ok; 4xx except 429 permanent;
-- everything else → next base, then retry. 403 is the Worker saying "not
-- trusted" (pending again, or blocked): keep the message, the poll will tell.
local function upload_once(v1)
  for _, base in ipairs(targets(serving or bases[1])) do
    local url = base .. "/" .. cfg.TOPIC .. "?dev=" .. dev_id
    local code = http_req("POST", url, auth_headers("text/plain; charset=utf-8"), v1, UPLOAD_TIMEOUT)
    if code >= 200 and code < 300 then return "ok" end
    if code == 403 then
      log.warn("gw", "upload refused (403): not trusted on the web; keeping the queue")
      trusted = false
      return "retry"
    end
    if code >= 400 and code < 500 and code ~= 429 then
      log.error("gw", "upload rejected permanently", code, base)
      return "drop"
    end
    log.warn("gw", "upload failed", code, base)
  end
  return "retry"
end

local function uploader()
  wait_ip()
  local fails = 0
  while true do
    local item = queue[1]
    if not item then
      sys.waitUntil("GW_UPLOAD", 15000)
    elseif not trusted then
      sys.waitUntil("GW_TRUST", 15000)   -- pending/blocked: the queue waits for the web
    else
      -- Encrypt once, reuse — except the one re-seal that adds the [原时间]
      -- prefix when the first attempt is already ≥120 s after receipt.
      if item.raw and not item.prefixed then
        local now = os.time()
        if now >= CLOCK_VALID_S and item.raw.ts >= CLOCK_VALID_S and now - item.raw.ts >= PREFIX_AFTER_S then
          local ok, v1 = pcall(seal_item, item, true)
          if ok and v1 then
            item.v1 = v1
            if #v1 <= FSKV_MAX then kv_set("q:" .. item.seq, v1) end
          end
          item.prefixed = true
        end
      end
      item.tries = item.tries + 1
      local r = upload_once(item.v1)
      if r == "ok" or r == "drop" then
        dequeue(item)
        fails = 0
        collectgarbage()
      else
        fails = fails + 1
        sys.wait(math.min(15000 * fails, 300000))   -- linear 15 s × n, cap 5 min
      end
    end
  end
end

-- --- outbox: poll, send, ack ---------------------------------------------

-- ?dev= on every route: the Worker looks a module up by it before checking the bearer.
local function ack(base, id, ok, detail)
  local body = M.build_ack(id, ok, detail)
  local sent = post_all(base, "/api/outbox/ack?dev=" .. dev_id, "application/json", body, ACK_TIMEOUT)
  if not sent then log.warn("gw", "ack not delivered for #" .. id) end
  return sent
end

-- Returns code, text. Only "SEND_OK" is a success.
local function send_sms(to, body, sim)
  if sim ~= "" and sim ~= "0" then
    return "SEND_SUBSCRIPTION_UNAVAILABLE", "本设备只有 SIM 1（请求 sim=" .. sim .. "）"
  end
  if blank(to) or body == "" then return "SEND_EMPTY", "空号码或内容" end
  local ok = sms.send(to, body)
  if ok == nil then
    -- nil (not false) is "sms is busy": the modem still owes the SMS_SENT of an
    -- earlier send that timed out. Drain that report, then try exactly once
    -- more — otherwise the row is acked as failed without ever being attempted.
    log.warn("gw", "sms busy; waiting for the previous SMS_SENT")
    sys.waitUntil("SMS_SENT", SEND_WAIT)
    ok = sms.send(to, body)
  end
  if not ok then
    local st
    pcall(function() st = mobile.status() end)
    if type(st) == "number" and st ~= 1 and st ~= 5 and st ~= 6 and st ~= 7 then
      return "SEND_NO_SERVICE", "未注册网络 status=" .. st
    end
    return "SEND_GENERIC_FAILURE", "sms.send 返回 " .. tostring(ok)
  end
  local got, result, rp_cause, rp_cause_str, _, error_code = sys.waitUntil("SMS_SENT", SEND_WAIT)
  if not got then return "SEND_TIMEOUT", "45s 内未收到 SMS_SENT 回执（可能已发出）" end
  if result then return "SEND_OK", "回执成功" end
  return "SEND_GENERIC_FAILURE", string.format("rp_cause=%s %s error_code=%s",
    tostring(rp_cause), tostring(rp_cause_str), tostring(error_code))
end

local function handle_row(base, row)
  local id = row.id
  local prior = M.ring_get(ring, id)
  if prior then
    -- Ack lost and the row came back: re-ack with the prior outcome, never
    -- re-send (a timed-out send may well have gone out; duplicating it is the
    -- worse mistake). detail is the fixed replay note (critic report G7) so the
    -- web shows why the row resolved without a new attempt — independent of the
    -- prior code (ack_detail would otherwise collapse a SEND_OK to its attempt).
    log.warn("gw", "outbox #" .. id .. " re-served; re-acking " .. prior)
    ack(base, id, prior == "SEND_OK", "此前已处理，重发请求已忽略")
    return
  end
  local attempt = M.new_attempt_id()
  local code, text
  if #row.payload > OUTBOX_MAX then
    -- Bound the payload before the non-yielding pure-Lua GCM decrypt so an
    -- oversized row can't starve wdt.feed (any web user could enqueue one).
    code, text = "OUTBOX_DECRYPT_FAILED", "密文过大 " .. #row.payload .. " 字节"
  else
    local plain = gcm.open(key32, row.payload)
    if not plain then
      code, text = "OUTBOX_DECRYPT_FAILED", "密文无法解密（SMS_KEY 不匹配？）"
    else
      local ok, cmd = pcall(json.decode, plain)
      if not ok or type(cmd) ~= "table" then cmd = {} end
      local to = type(cmd.to) == "string" and cmd.to or ""
      local body = type(cmd.body) == "string" and cmd.body or ""
      local sim = cmd.sim
      if type(sim) == "number" then sim = tostring(math.tointeger(sim) or sim) end
      if type(sim) ~= "string" then sim = "" end
      code, text = send_sms(to, body, sim)
    end
  end
  local ok = code == "SEND_OK"
  if ok or code == "SEND_TIMEOUT" then
    ring = M.ring_put(ring, id, code)
    kv_set("done", ring)
  end
  last_send = ok and ("成功 [" .. attempt .. "]") or (code .. "｜" .. text .. " [" .. attempt .. "]")
  log.info("gw", "outbox #" .. id, code, text, attempt)
  ack(base, id, ok, M.ack_detail(code, text, attempt))
  collectgarbage()
end

-- --- registration, trust, commands ------------------------------------------

-- The Worker's verdict on this device. Logged once per change; a change seen by
-- the poll re-registers (so the card's ls/ota refresh) and wakes the uploader.
local function set_trust(status, from_poll)
  local was = trust
  trust, trusted = status, (status == "trusted")
  if status == was then return end
  if trusted then log.info("gw", "trusted on the web")
  elseif status == "blocked" then log.warn("gw", "blocked on the web: uploads and sends paused")
  else log.warn("gw", "waiting for trust on the web (dev " .. tostring(dev_id) .. ")") end
  if from_poll then reg_due = true end
  if trusted then sys.publish("GW_TRUST") end
end

-- POST /api/register: the encrypted self-description (built by main.lua, which
-- knows the OTA state and boot counter). Non-2xx: try again next cycle.
local function register()
  if not _G.gw_reg then log.error("gw", "no _G.gw_reg (main.lua missing): cannot register"); return end
  local v1 = gcm.seal(key32, _G.gw_reg(sim_label(), last_send))
  for _, b in ipairs(targets(serving or bases[1])) do
    local code, _, body = http_req("POST", b .. "/api/register?dev=" .. dev_id,
      auth_headers("text/plain; charset=utf-8"), v1, ACK_TIMEOUT)
    if code >= 200 and code < 300 then
      local ok, t = pcall(json.decode, body)
      local st = (ok and type(t) == "table" and type(t.status) == "string") and t.status or "?"
      log.info("gw", "registered:", st)
      set_trust(st, false)
      reg_due, reg_polls = false, 0
      return
    end
    log.warn("gw", "register failed", code, b)
  end
end

-- One web command per poll: main.lua runs it (reboot/bases/ota — the OTA download
-- needs the base), gw.lua acks. Always ack; main.lua's reboots are on timers, so
-- the ack goes out first.
local function run_cmd(base, cmd)
  local id = tonumber(cmd.id)
  id = id and math.tointeger(id)
  if not id then log.warn("gw", "cmd without an integer id ignored"); return end
  local ok, detail = false, "no gw_cmd"
  if _G.gw_cmd then ok, detail = _G.gw_cmd.run(cmd, base) end
  local sent = post_all(base, "/api/cmd/ack?dev=" .. dev_id, "application/json", M.build_ack(id, ok, detail), ACK_TIMEOUT)
  if not sent then log.warn("gw", "cmd ack not delivered for #" .. id) end
end

local function poll_once()
  for _, base in ipairs(bases) do
    local code, _, body = http_req("GET", base .. "/api/poll?dev=" .. dev_id, auth_headers(), nil, POLL_TIMEOUT)
    if code == 200 then
      local p = M.parse_poll(body)
      if p then
        poll_fail, serving = 0, base
        polls = polls + 1
        if _G.gw_alive then _G.gw_alive() end   -- main.lua's boot health: the server answered
        set_trust(p.status, true)
        if trusted then
          for _, row in ipairs(p.rows) do
            perr("row #" .. tostring(row.id), pcall(handle_row, base, row))
          end
          if p.cmd then perr("cmd #" .. tostring(p.cmd.id), pcall(run_cmd, base, p.cmd)) end
        end
        return true
      end
      log.warn("gw", "poll body is not a status object", base)
    else
      -- A definitive "I do not know you": the web pressed 忘记 and deleted the
      -- devices row. Only /api/register recreates it (the poll cannot), so
      -- re-introduce ourselves on the next cycle instead of going dark until
      -- the 30-minute register tick.
      if code == 403 or code == 404 then reg_due = true end
      log.warn("gw", "poll failed", code, base)
    end
  end
  poll_fail = poll_fail + 1
  if poll_fail >= POLL_FAIL_REBOOT then
    log.error("gw", "poll failed " .. poll_fail .. " times in a row; rebooting")
    -- This boot was fine, only the network was not: clear main.lua's counter so
    -- an outage cannot walk a healthy module into rescue mode (where inbound SMS
    -- are dropped) three reboots later. While an OTA copy is active the counter
    -- is left alone — OTA code that can never reach the Worker must still be
    -- reverted, which is exactly what those failed boots count towards.
    if not _G.gw_ota or _G.gw_ota.active() == "-" then kv_set("boot_fail", 0) end
    rtos.reboot()
  end
  return false
end

local function poller()
  wait_ip()
  local every = math.max(1, math.floor(REGISTER_EVERY_MS / (cfg.POLL_MS or 30000)))
  while true do
    if reg_due or reg_polls >= every then perr("register", pcall(register)) end
    perr("poll", pcall(poll_once))
    reg_polls = reg_polls + 1
    collectgarbage()
    sys.wait(cfg.POLL_MS or 30000)
  end
end

-- --- inbound SMS -------------------------------------------------------------

-- The #status line, published to main.lua as _G.gw_status_line (M.start). main.lua
-- owns SMS command handling — it has to work with gw.lua broken or absent — but it
-- cannot see any of this: the queue depth, the trust state, the signal. So it asks.
local function status_line()
  local function safe(f, ...) local ok, v = pcall(f, ...); if ok and v ~= nil then return tostring(v) end return "-" end
  local ip = "-"
  if socket and socket.localIP then ip = safe(socket.localIP) end
  -- ota= / boot= come from main.lua (OTA scripts active, failed-boot counter);
  -- "-" / 0 when gw.lua runs standalone.
  local ota = _G.gw_ota and safe(_G.gw_ota.active) or "-"
  return string.format("%s csq=%s net=%s ip=%s q=%d gcm=%s fw=%s trust=%s ota=%s boot=%d",
    tostring(M.VERSION), safe(mobile.csq), safe(mobile.status), ip, #queue,
    _G.GCM_OK and "ok" or "FAIL", safe(rtos.version), trust, ota, tonumber(kv_get("boot_fail")) or 0)
end

-- Every message that reaches gw.lua is an ordinary message: main.lua's callback has
-- already taken (and NOT forwarded) anything that carried a valid signature, so a "#…"
-- arriving here is a probe or a typo and the user should see it on the web page.
local function on_sms(num, txt, metas)
  num = tostring(num == nil and "" or num)
  txt = tostring(txt == nil and "" or txt)
  if num == "" then num = "未知" end
  enqueue(num, txt, os.time())
end

-- Missed-call forwarding: the first INCOMINGCALL of a ring is the event; the
-- state repeats on every ring, so it is debounced until the call ends. We
-- never touch cc.init()/cc.hangUp() (unverified without an audio codec) — the
-- call simply rings out, which is exactly what makes it a missed call.
local ring_gen = 0
local function on_cc(state)
  if state == "INCOMINGCALL" then
    if ringing then return end
    ringing = true
    -- Belt and braces: if the end-of-call state never arrives (firmware
    -- variance), a 60 s timer re-arms us so later calls are not swallowed
    -- forever. The generation counter keeps a stale timer from clearing a
    -- newer call's debounce.
    ring_gen = ring_gen + 1
    local gen = ring_gen
    sys.timerStart(function() if ring_gen == gen then ringing = false end end, 60000)
    local num
    if cc and cc.lastNum then
      local ok, n = pcall(cc.lastNum)
      if ok and type(n) == "string" and n:match("%S") then num = n end
    end
    enqueue(num or "未知号码", "未接来电", os.time())
  elseif state == "DISCONNECTED" or state == "HANGUP_CALL_DONE" then
    ringing = false
  end
end

-- Test hook: a snapshot of the runtime state (used by the tests and the e2e driver).
function M._state()
  return { queue = queue, ring = ring, dev_id = dev_id, bases = bases, serving = serving,
           last_send = last_send, poll_fail = poll_fail, polls = polls, ringing = ringing,
           trust = trust, trusted = trusted, started = started }
end

-- ---------------------------------------------------------------------------
-- Boot
-- ---------------------------------------------------------------------------

function M.start(c)
  cfg = c or {}
  M.VERSION = _G.VERSION or "0.0.0"
  local ver, bsp = "?", "?"
  pcall(function() ver = rtos.version(); bsp = rtos.bsp() end)
  log.info("gw", "boot", _G.PROJECT, M.VERSION, ver, bsp)

  if fskv then
    local iok, ir = pcall(fskv.init)
    if not iok then log.error("gw", "fskv.init", ir)
    elseif ir == false then
      log.error("gw", "fskv.init returned false — flash persistence unavailable (dev_id/queue/done-ring will not survive a reboot)")
    end
  end

  -- Identity minted by main.lua at first boot: dev_id (16 hex) and the bearer dev_secret (32 hex).
  dev_id, dev_secret = kv_get("dev_id"), kv_get("dev_secret")
  local function ident_valid()
    return type(dev_id) == "string" and dev_id:match("^[0-9a-f]+$") ~= nil
      and type(dev_secret) == "string" and #dev_secret == 32 and dev_secret:match("^[0-9a-f]+$") ~= nil
  end
  if not ident_valid() and type(_G.gw_ident) == "table" then
    -- fskv could not keep it (worn/full flash). main.lua hands the freshly minted
    -- identity over in RAM so the module still registers — a new id every boot is
    -- visible and fixable on the web; silence is not.
    log.warn("gw", "device identity not in fskv — using main.lua's in-RAM copy")
    dev_id, dev_secret = _G.gw_ident.id, _G.gw_ident.secret
  end
  local ident_ok = ident_valid()
  if not ident_ok then log.error("gw", "no device identity (main.lua mints it) — network disabled") end

  -- A bad SMS_KEY must NEVER fall back to a constant key and keep uploading:
  -- that would encrypt real messages under a publicly-known key (readable by
  -- anyone with the ciphertext). Any parse failure — or an all-zero key, which
  -- is a valid-looking placeholder — disables uploads through GCM_OK below.
  local key_ok = true
  local okk
  okk, key32 = pcall(function() return (tostring(cfg.SMS_KEY):fromHex()) end)
  if not okk or type(key32) ~= "string" or #key32 ~= 32 then
    log.error("gw", "SMS_KEY must be 64 hex chars — uploads disabled")
    key32 = string.rep("\0", 32); key_ok = false
  elseif key32 == string.rep("\0", 32) then
    log.error("gw", "SMS_KEY is all zeros (unedited placeholder?) — uploads disabled")
    key_ok = false
  end

  -- If GCM is broken, or the key is invalid, the ciphertext would be garbage or
  -- publicly readable: keep running so #status can report it, but never upload.
  local ok, r = pcall(gcm.selftest)
  _G.GCM_OK = (ok and r == true and key_ok) or false
  if _G.GCM_OK then log.info("gw", "gcm selftest ok")
  elseif not key_ok then log.error("gw", "SMS_KEY invalid — uploads disabled")
  else log.error("gw", "GCM SELF-TEST FAILED — uploads disabled", r) end

  bases = M.parse_bases(cfg.BASES)   -- main.lua already merged the fskv "bases" override in
  if #bases == 0 then log.error("gw", "no bases configured") end

  local d = kv_get("done")
  ring = type(d) == "string" and d or ""
  load_queue()

  -- Hand main.lua the rich #status line. Set here, before the early return below, so a
  -- dormant gw.lua (no key/identity/base) still answers with what it knows rather than
  -- main.lua's bare RESCUE line.
  _G.gw_status_line = status_line

  sms.setNewSmsCb(function(num, txt, metas)
    perr("sms cb", pcall(on_sms, num, txt, metas))
  end)
  sys.subscribe("CC_IND", function(state)
    perr("cc cb", pcall(on_cc, state))
  end)

  -- Without a key, an identity or a base there is nothing to talk to the Worker
  -- with: keep the callbacks (so a signed #status still answers), start no task.
  if not (key_ok and ident_ok and #bases > 0) then
    log.error("gw", "network tasks not started (key/identity/bases)")
    return M
  end

  if mobile.setAuto then perr("setAuto", pcall(mobile.setAuto, 10000, 30000, 8, true, 60000)) end
  if socket and socket.setDNS then
    pcall(socket.setDNS, nil, 1, "223.5.5.5")
    pcall(socket.setDNS, nil, 2, "119.29.29.29")
  end

  -- Tasks restart on an uncaught error rather than silently dying.
  local function forever(name, fn)
    sys.taskInit(function()
      while true do
        perr(name .. " task", pcall(fn))
        sys.wait(5000)
      end
    end)
  end
  started = true
  forever("uploader", uploader)
  forever("poller", poller)
  log.info("gw", "started dev=" .. dev_id, "bases", #bases, "queue", #queue)
  return M
end

return M
