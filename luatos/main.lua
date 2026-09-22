-- main.lua — Air780EHV SMS gateway boot stub. Flashed ONCE, never updated over
-- the air, so it stays small and boring: count boots, arm the watchdog, build
-- the config (DEFAULTS ← config.lua ← fskv "bases"), mint the device identity,
-- load gw.lua (or its OTA copy /ota_gw.lua) and keep the last line of defence
-- the app can never take away: the boot-loop guard with its OTA revert, the
-- OTA installer, the web command runner (_G.gw_cmd), the signed-SMS command
-- channel and a rescue mode that still registers with the Worker and takes its
-- commands when gw.lua cannot start. Nothing is provisioned over SMS: SMS_KEY
-- comes from config.lua, trust is granted on the web, and the SMS commands are
-- authenticated with that same key — there is no phone number to configure.
-- Needs nothing from gw.lua/gcm.lua at load time.
PROJECT = "smsgw"
VERSION = "2.1.0"
sys = require("sys")
require("sysplus")

local DEFAULTS = { BASES = "https://777310753.xyz,https://20150411.xyz",
                   TOPIC = "sms-7f3a9c2b1e0d", NAME = "Air780EHV", POLL_MS = 120000 }
local OTA_NAMES = { "gw", "gcm" }
local OTA_USAGE = "usage: #ota clear | #ota gw|gcm <hmac-sha256 hex>"
local HEALTH_TICK = 30000      -- one loop timer sequences the health rule and the rescue retry
local ALIVE_OK_MS = 300000     -- 5 min up AND the Worker answered a poll = healthy boot
local ALIVE_MAX_MS = 900000    -- 15 min without an answer: OTA code presumed broken / rescue retries anyway
-- Rescue is the one loop an OTA can never reach (this file returns before gw.lua is loaded),
-- so this number is frozen for the life of the board. At 60 s a board that falls into rescue
-- spends ~230 MB/month polling and eats a 200 MB SIM inside one month — turning "reachable and
-- fixable" into "unreachable". 240 s still gives two command fetches per ~6.5 min rescue cycle
-- (ALIVE_OK_MS reboots it at 5 min), and the instant channel is a signed SMS, not this loop.
local RESCUE_POLL_MS = 240000

local function kv_get(k) local ok, v = pcall(fskv.get, k); if ok then return v end; return nil end
local function kv_set(k, v) local ok, r = pcall(fskv.set, k, v); return ok and r end
local function clear_boot()   -- → true when the counter is back to 0 (del when set fails: flash full/worn)
  if kv_set("boot_fail", 0) then return true end
  pcall(fskv.del, "boot_fail")
  return (tonumber(kv_get("boot_fail")) or 0) == 0
end
-- sms.send returns nil while the modem still owes an SMS_SENT: retry once after 50 s.
local function reply(num, text)
  local ok, sent = pcall(sms.send, num, text)
  if not (ok and sent) then sys.timerStart(function() pcall(sms.send, num, text) end, 50000) end
end
-- gw.lua's M.json_escape, duplicated for the same reason (the register blob is built here).
local function jesc(s)
  s = tostring(s == nil and "" or s)
  return (s:gsub('[%c"\\]', function(c)
    if c == '"' then return '\\"' elseif c == '\\' then return '\\\\'
    elseif c == '\n' then return '\\n' elseif c == '\r' then return '\\r' elseif c == '\t' then return '\\t' end
    local b = c:byte()
    if b < 0x20 then return string.format('\\u%04x', b) end
    return c
  end))
end

pcall(fskv.init)
local boot_fail = (tonumber(kv_get("boot_fail")) or 0) + 1
kv_set("boot_fail", boot_fail)
-- Watchdog before any OTA code runs: a script that busy-loops resets the module
-- in ~9 s, which counts as a failed boot and gets it reverted. gw.lua has none.
if wdt then pcall(function() wdt.init(9000); sys.timerLoopStart(wdt.feed, 3000); _G.WDT_ARMED = true end) end

-- Commit-confirm for the `bases` override, because this is the one setting that can put the
-- module somewhere it can never be reached from again: a typo'd or since-dead domain leaves it
-- talking to nothing, and the web command that would fix it travels over the very link that is
-- broken. So an override is PROVISIONAL until a poll actually comes back from it; one that never
-- does is dropped after BASES_TRIES boots and the built-in domains take over. Once confirmed it
-- is permanent — a later outage on a domain that has worked must never silently roll back.
local BASES_TRIES = 3
local rescue_mode = false   -- set in the boot_fail>=3 block below; read by cmd_exec and the health timer
local ovr = kv_get("bases")
local ovr_active = type(ovr) == "string" and ovr ~= ""
local ovr_ok = ovr_active and tostring(kv_get("bases_ok") or "") == "1"
-- fskv.del is unverified and can silently fail on worn/full flash, exactly the case clear_boot()
-- is written to survive. For the three keys that decide where the module talks, a failed del would
-- strand it on a dead override while the log claims it reverted, so verify and, if a key will not
-- go, tombstone it with "" — merged() and ovr_active both read "" as "no override".
local function kv_forget(k)
  pcall(fskv.del, k)
  if kv_get(k) ~= nil then kv_set(k, "") end
end
local function bases_forget()
  kv_forget("bases"); kv_forget("bases_ok"); kv_forget("bases_try")
  ovr_active, ovr_ok = false, false
end
-- The provisional-override boot counter runs further down, once _G.gw_ota is defined: an override
-- must not be blamed for an unanswered boot while an unproven OTA copy is the more likely reason
-- nothing reached the Worker (that copy's own revert is the right remedy).

-- Config = DEFAULTS ← config.lua (REQUIRED: SMS_KEY) ← fskv "bases" (web `bases` command / #url).
local file_cfg
-- One quoted string on any line that mentions require: Luatools' project scanner takes the
-- FIRST quote to the LAST quote on such a line as the module name, so the compact pcall form
-- had it asking for a file called: config"); if ok and type(t) == "table
local function load_config()
  return require("config")
end
do
  local ok, t = pcall(load_config)
  if ok and type(t) == "table" then file_cfg = t end
end
local function merged()
  local c = {}
  for _, src in ipairs({ DEFAULTS, file_cfg or {} }) do for k, v in pairs(src) do c[k] = v end end
  local kv = kv_get("bases")
  if type(kv) == "string" and kv ~= "" then c.BASES = kv end
  return c
end
local function key32_of(c)
  local h = c.SMS_KEY
  if type(h) ~= "string" or #h ~= 64 or not h:match("^%x+$") then return nil end
  local ok, k = pcall(function() return (h:fromHex()) end)
  if ok and type(k) == "string" and #k == 32 and k ~= string.rep("\0", 32) then return k end
end
local function split_bases(v)   -- config/fskv list → table; lenient (http:// allowed for the bench)
  local out = {}
  local function add(s)
    s = tostring(s == nil and "" or s):gsub("^%s+", ""):gsub("%s+$", ""):gsub("/+$", "")
    if s:match("^https?://%S+$") then out[#out + 1] = s end
  end
  if type(v) == "table" then for _, s in ipairs(v) do add(s) end
  elseif type(v) == "string" then for s in v:gmatch("[^,%s]+") do add(s) end end
  return out
end
-- The web `bases` command / #url: https only, ≤5, nothing that would swallow the "/api/…" the
-- module appends (query, fragment, quotes). Same rule as the Worker's /api/cmd validation.
local function valid_bases(v)
  local out = {}
  for s in tostring(v == nil and "" or v):gmatch("[^,]+") do
    s = s:gsub("^%s+", ""):gsub("%s+$", ""):gsub("/+$", "")
    local rest = #s <= 120 and s:match("^https://[A-Za-z0-9.-]+(.*)$")
    if not rest then return nil end
    rest = rest:gsub("^:%d+", "")
    if rest ~= "" and not rest:match("^/[A-Za-z0-9._~/-]*$") then return nil end
    out[#out + 1] = s
  end
  return (#out >= 1 and #out <= 5) and out or nil
end

-- Identity: dev_id (16 hex) is the ?dev= / "d" the Worker and the web know the module by,
-- dev_secret (32 hex) is its bearer on every request. Both minted once from the TRNG.
-- crypto.trng returns NOTHING when the TRNG errors, so indexing its result
-- directly would throw here, in the main chunk, before sys.run() — a brick that
-- no OTA can repair. Guard it and boot on without an identity instead.
local function rnd_hex(n)
  local ok, s = pcall(crypto.trng, n)
  if not (ok and type(s) == "string" and #s == n) then return nil end
  local hok, h = pcall(function() return (s:toHex()):lower() end)
  if hok and type(h) == "string" and #h == n * 2 then return h end
  return nil
end
local dev_id, dev_secret = kv_get("dev_id"), kv_get("dev_secret")
if type(dev_id) ~= "string" or not dev_id:match("^[0-9a-f]+$") then
  dev_id = rnd_hex(8); if dev_id then kv_set("dev_id", dev_id) end
end
if type(dev_secret) ~= "string" or #dev_secret ~= 32 or not dev_secret:match("^[0-9a-f]+$") then
  dev_secret = rnd_hex(16); if dev_secret then kv_set("dev_secret", dev_secret) end
end
if dev_id and dev_secret then
  -- Handed to gw.lua in RAM as well: on worn flash the fskv writes above can
  -- fail, and an identity that only lives in fskv would leave the module
  -- invisible forever (no register, no poll, not even a pending card).
  _G.gw_ident = { id = dev_id, secret = dev_secret }
else
  log.error("main", "TRNG unavailable: no device identity this boot — network disabled")
  dev_id, dev_secret = dev_id or "", dev_secret or ""
end
local function hdr(ctype)
  local h = { ["Authorization"] = "Bearer " .. dev_secret }
  if ctype then h["Content-Type"] = ctype end
  return h
end
-- http.request(...).wait() → code, body; in a task only. -1 = network failure / thrown error.
local function req(method, url, headers, body, timeout)
  local c = merged()
  local ok, code, _, rbody = pcall(function()
    local opts = { timeout = timeout }
    if c.CA_PEM then return http.request(method, url, headers, body, opts, c.CA_PEM).wait() end
    return http.request(method, url, headers, body, opts).wait()
  end)
  if not ok or type(code) ~= "number" then return -1, "" end
  return code, rbody or ""
end
local function mob(name) local ok, v = pcall(function() return mobile[name]() end); return (ok and type(v) == "string") and v or "" end

-- ---- OTA: /ota_<name>.lua overrides the flashed <name>.lua ------------------
local function ota_path(name) return "/ota_" .. name .. ".lua" end
local function ota_read(name)   -- source string, or nil when no OTA copy exists
  local f = io.open(ota_path(name), "rb")
  if not f then return nil end
  local src = f:read("*a"); f:close()
  return src or ""
end
local function ota_exists(name) local f = io.open(ota_path(name), "rb"); if f then f:close() end; return f ~= nil end
local function ota_remove() for _, n in ipairs(OTA_NAMES) do pcall(os.remove, ota_path(n)) end end
-- Luatools decides which lib files a project needs by scanning the script TEXT for the word
-- require followed by a name, and it neither resolves variables nor skips comments. Written the
-- obvious way, the dynamic call below made it demand a "name.lua" that cannot exist and refuse to
-- flash with 缺少库文件. Through an alias it is the identical call with nothing to misread — which
-- is also why no comment in this file spells that call out literally.
-- ...but invisible also means Luatools will happily flash a package with gw.lua and gcm.lua
-- MISSING: it only ever demanded config.lua, so a flash that the tool called successful left the
-- module boot-looping on "module 'gw' not found" into rescue mode. These two lines never execute;
-- they exist so the scanner sees both names and refuses to flash without them.
if false then require("gw") end
if false then require("gcm") end
local luaRequire = require
function _G.load_module(name)
  local src = ota_read(name)
  local chunk, err = src and load(src, "=ota_" .. name)
  if chunk then
    local ok, m = pcall(chunk)
    if ok and type(m) == "table" then
      log.info("main", "ota", name, "loaded", #src)
      package.loaded[name] = m   -- a later require of this name gets the running copy, not the flashed file
      return m
    end
    err = m
  end
  if src then   -- half-written or broken copy: drop it, so #status/register never show an OTA copy that is not running
    log.error("main", "ota", name, "unusable, removed:", err); pcall(os.remove, ota_path(name))
  end
  return luaRequire(name)
end
_G.gw_ota = {}
function _G.gw_ota.active()
  local t = {}
  for _, n in ipairs(OTA_NAMES) do if ota_exists(n) then t[#t + 1] = n end end
  return #t > 0 and table.concat(t, ",") or "-"
end
function _G.gw_ota.clear(reply_to)
  ota_remove(); clear_boot()
  if reply_to then reply(reply_to, "ota cleared rebooting") end
  sys.timerStart(rtos.reboot, 10000)
end

-- Provisional `bases` override: it is trusted only after a poll comes back from it (gw_alive
-- below sets bases_ok), so one that never answers is dropped after BASES_TRIES boots and the
-- built-in domains take over. Placed here, after _G.gw_ota, on purpose: while an unproven OTA
-- copy is present its own revert is the correct remedy for "nothing reached the Worker", so the
-- hand-entered domain must not be spent on the OTA copy's failure to poll — count only with no
-- OTA copy active. bases_try is read defensively: a first unconfirmed boot has no key (→ try 1),
-- and a present-but-corrupt value (negative / non-integer / out of range on worn flash) drops the
-- unconfirmed override now rather than looping forever or pinning it — the built-ins are the safe
-- fallback. A counter that cannot even be written is the same: drop, don't stay un-droppable.
if ovr_active and not ovr_ok and _G.gw_ota.active() == "-" then
  local raw = kv_get("bases_try")
  local tries
  if raw == nil then
    tries = 1
  else
    local n = math.tointeger(tonumber(raw) or -1)
    tries = (n and n >= 0 and n < BASES_TRIES) and (n + 1) or BASES_TRIES
  end
  if tries >= BASES_TRIES then
    bases_forget()
    log.error("main", "bases override unconfirmed after " .. (BASES_TRIES - 1) .. " tries — reverted to the built-in domains")
  elseif not kv_set("bases_try", tries) then
    bases_forget()
    log.error("main", "bases override counter unwritable — reverted to the built-in domains")
  else
    log.warn("main", "bases override unconfirmed, boot " .. tries .. "/" .. BASES_TRIES)
  end
end
-- Verify + write. MAC over "<name>\n<bytes>" — the browser (worker page) and test/ota-sign.sh
-- sign the same input, so a gw.lua signed for gw cannot be installed as gcm.
local function ota_install(name, body, hmac_hex)   -- → reason | nil, bytes
  local key32 = key32_of(merged())
  if not key32 then return "no key" end
  if name ~= "gw" and name ~= "gcm" then return "name" end
  if type(body) ~= "string" or #body == 0 or #body > 200000 then return "size" end
  local mac = crypto.hmac_sha256(name .. "\n" .. body, key32)
  if type(mac) ~= "string" or mac:lower() ~= tostring(hmac_hex):lower() then return "hmac" end
  if not load(body, "=ota_" .. name) then return "compile" end
  local f = io.open(ota_path(name), "wb")
  if not f then return "write" end
  local wok = f:write(body)
  local cok = f:close()
  -- LittleFS commits at close and its close result is swallowed: read it back.
  if not (wok and cok and ota_read(name) == body) then pcall(os.remove, ota_path(name)); return "write" end
  if not clear_boot() then pcall(os.remove, ota_path(name)); return "fskv" end   -- stuck ≥3 → it would be reverted at boot
  return nil, #body
end
local function ota_fetch(base, name, hmac_hex)   -- in a task; the staged script comes from the Worker
  if name ~= "gw" and name ~= "gcm" then return "name" end
  if type(base) ~= "string" or base == "" then return "base" end
  local code, body = req("GET", base .. "/api/ota/get?dev=" .. dev_id .. "&name=" .. name, hdr(), nil, 60000)
  if code ~= 200 then return "http " .. tostring(code) end
  return ota_install(name, body, hmac_hex)
end

-- ---- web commands (from the poll) and their SMS twins ----------------------
-- _G.gw_cmd.run(cmd, base) → ok, detail. cmd = {id?, type="reboot"|"bases"|"ota", ...}; base is
-- where an OTA script is downloaded from. Runs in a task (the download waits). The caller acks
-- with (ok, detail) — before the reboot, which is on a timer. A cmd whose id is the last one
-- acked is answered from fskv and not run again (the ack got lost; the Worker re-served it).
-- require_sig is true for anything that arrived over the network: `bases` then has to carry an
-- HMAC-SHA256 under SMS_KEY. It is false only on the "#url" SMS (see url_cmd), which carries
-- its own signature over the whole message under the very same key.
local function cmd_exec(cmd, base, require_sig)
  local t = cmd.type
  if t == "reboot" then
    clear_boot(); sys.timerStart(rtos.reboot, 5000); return true, "rebooting"
  elseif t == "bases" then
    -- `bases` is the one command that can take the module away for good: point it at another
    -- server and the real Worker can never reach it again — block/forget go nowhere and the only
    -- recovery is a physical reflash. TLS verification is off by default (no CA_PEM), so an
    -- on-path attacker — or a compromised Worker — could otherwise inject one. So a
    -- poll-delivered `bases` must be signed with SMS_KEY, which the server never holds: MAC over
    -- "bases\n" .. the value, exactly like the OTA "<name>\n<bytes>". Verify the value AS
    -- RECEIVED, never the re-normalised list — the browser signed the bytes it sent and the
    -- Worker stores them unchanged (its normalisation is the same rule, so it is a no-op here).
    if require_sig then
      local key32 = key32_of(merged())
      if not key32 then return false, "no key" end
      if type(cmd.value) ~= "string" then return false, "hmac" end
      local mac = crypto.hmac_sha256("bases\n" .. cmd.value, key32)
      if type(mac) ~= "string" or mac:lower() ~= tostring(cmd.hmac or ""):lower() then return false, "hmac" end
    end
    local list = valid_bases(cmd.value)
    if not list then return false, "bad bases" end
    if not kv_set("bases", table.concat(list, ",")) then return false, "fskv" end
    -- Provisional until it answers: see BASES_TRIES above. kv_forget (not a bare del) so that a
    -- del that silently fails cannot leave bases_ok="1" behind and make the new override born
    -- already-confirmed — the tombstone "" reads as "not confirmed".
    kv_forget("bases_ok"); kv_forget("bases_try")
    -- Do NOT mark the override active for the rest of THIS boot. The next boot re-reads fskv, and
    -- until the reboot lands gw.lua's poller is still hitting the OLD base list; a 200 from there
    -- must not confirm the brand-new override, so leave gw_alive a no-op until we come back up.
    ovr_active, ovr_ok = false, false
    -- Rescue-issued `bases`: keep boot_fail>=3 so the next boot is rescue too and can confirm the
    -- new domain on its very first poll. Clearing it would run the broken gw.lua that caused rescue,
    -- which crash-loops and spends the override's tries before anything ever reaches the new domain.
    if not rescue_mode then clear_boot() end
    sys.timerStart(rtos.reboot, 5000); return true, "rebooting"
  elseif t == "ota" then
    local err, n = ota_fetch(base, cmd.name, cmd.hmac)
    if err then return false, err end
    sys.timerStart(rtos.reboot, 10000); return true, tostring(n)
  end
  return false, "bad type"
end
_G.gw_cmd = {}
function _G.gw_cmd.run(cmd, base)
  if type(cmd) ~= "table" then return false, "bad cmd" end
  local id = tonumber(cmd.id)
  if id and id == tonumber(kv_get("last_cmd")) then
    local res = tostring(kv_get("last_cmd_res") or "")
    log.warn("main", "cmd #" .. id .. " already ran; re-acking", res)
    return res:sub(1, 3) == "ok:", (res:gsub("^%a+:", ""))
  end
  local ok, okr, detail = pcall(cmd_exec, cmd, base, true)   -- came off the poll: `bases` must be signed
  if not ok then okr, detail = false, "error " .. tostring(okr) end
  detail = tostring(detail == nil and "" or detail):sub(1, 200)
  log.info("main", "cmd", cmd.id, cmd.type, okr and "ok" or "fail", detail)
  if id then kv_set("last_cmd", id); kv_set("last_cmd_res", (okr and "ok:" or "fail:") .. detail) end
  return okr, detail
end
-- The "#url <list>" SMS sets `bases` without the separate "bases\n<value>" signature the
-- poll path requires: the whole SMS is already signed under SMS_KEY (sms_cmd below), so a
-- second MAC over the same bytes under the same key would prove nothing new. It is a LOCAL
-- on purpose — sms_cmd is its only caller, so the one unsigned-`bases` entry point in this
-- firmware is not reachable from anything that came off the network. A poll-delivered
-- command goes through _G.gw_cmd.run, which requires the HMAC. Keep it that way: an
-- unsigned `bases` reachable from the network is a permanent capture of the module.
local function url_cmd(value)
  local ok, okr, detail = pcall(cmd_exec, { type = "bases", value = value }, nil, false)
  if not ok then okr, detail = false, "error " .. tostring(okr) end
  detail = tostring(detail == nil and "" or detail):sub(1, 200)
  log.info("main", "cmd", "-", "url", okr and "ok" or "fail", detail)
  return okr, detail
end
-- "#ota gw|gcm <hmac>" by SMS: same download + install, replied to the sender. Every
-- configured base is tried, because this channel is used precisely when one of them is
-- unreachable; only a download failure ("http …") is worth another base — a bad hmac or a
-- script that will not compile fails the same way everywhere.
function _G.gw_ota.install(name, hmac_hex, reply_to)
  sys.taskInit(function()
    local ok, d = false, "no base"
    for _, b in ipairs(split_bases(merged().BASES)) do
      ok, d = _G.gw_cmd.run({ type = "ota", name = name, hmac = hmac_hex }, b)
      if ok or tostring(d):sub(1, 5) ~= "http " then break end
    end
    if ok then log.info("main", "ota", name, "installed", d) else log.error("main", "ota", name, d) end
    reply(reply_to, ok and ("ota ok " .. name .. " " .. d .. " rebooting") or ("ota fail: " .. d))
  end)
end

-- The self-description sent with /api/register (what the web card shows: name, SIM, firmware,
-- script version, OTA state, boot counter, IMEI/ICCID to tell modules apart). All keys always
-- present, strings escaped, numbers bare. gw.lua passes its SIM label and last-send line.
function _G.gw_reg(sim_name, ls)
  local ok, v = pcall(rtos.version); local fw = (ok and v ~= nil) and tostring(v) or ""
  local bok, b = pcall(rtos.bsp); local bsp = (bok and b ~= nil) and tostring(b) or ""
  return string.format('{"n":"%s","s":[{"slot":0,"name":"%s"}],"t":"4G","os":"LuatOS %s %s","v":"%s","ls":"%s"'
    .. ',"imei":"%s","iccid":"%s","imsi":"%s","num":"%s","fw":"%s","ver":"%s","ota":"%s","boot":%d}',
    jesc(merged().NAME), jesc(sim_name), jesc(fw), jesc(bsp), jesc(VERSION), jesc(ls),
    jesc(mob("imei")), jesc(mob("iccid")), jesc(mob("imsi")), jesc(mob("number")),
    jesc(fw), jesc(VERSION), jesc(_G.gw_ota.active()), tonumber(kv_get("boot_fail")) or boot_fail)
end

-- ---- boot health: alive = the Worker answered a poll ------------------------
-- gw.lua (and the rescue loop) call _G.gw_alive() after every 200 from /api/poll, trusted
-- or not. One loop timer, explicit sequencing:
--   normal: boot_fail → 0 once alive AND 5 min up; 15 min never alive while an OTA copy is
--           active → this boot failed (the counter was never cleared): reboot, so the third such
--           boot reverts the copies. Flashed code with no network: nothing — an outage must not
--           reboot-loop a healthy device.
--   rescue: retry a normal boot after 5 min AND one answered poll, else after 15 min regardless.
local up_ms, alive, cleared = 0, false, false   -- rescue_mode is declared up top (cmd_exec reads it)
function _G.gw_alive()
  alive = true
  -- The Worker answered, so whatever domain we reached it on works. Pin the override.
  if ovr_active and not ovr_ok then
    ovr_ok = true
    kv_set("bases_ok", "1"); pcall(fskv.del, "bases_try")
    log.info("main", "bases override confirmed")
  end
end
sys.timerLoopStart(function()
  up_ms = up_ms + HEALTH_TICK
  if rescue_mode then
    if (alive and up_ms >= ALIVE_OK_MS) or up_ms >= ALIVE_MAX_MS then
      if clear_boot() then
        log.warn("main", "rescue: retrying a normal boot"); rtos.reboot()
      else
        -- Dead flash: the stale counter would put the next boot straight back in
        -- rescue, every 5 minutes forever. Stay up and keep polling instead —
        -- the module remains reachable and the next tick retries the clear.
        log.error("main", "rescue: cannot clear boot_fail — staying in rescue and polling")
        up_ms, alive = 0, false
      end
    end
  elseif alive and not cleared and up_ms >= ALIVE_OK_MS then
    cleared = clear_boot()
  elseif not alive and up_ms >= ALIVE_MAX_MS and _G.gw_ota.active() ~= "-" then
    log.error("main", "no poll answered in 15 min with OTA code active: failed boot, rebooting")
    rtos.reboot()
  end
end, HEALTH_TICK)

-- ---- boot-loop guard → OTA revert → SMS foothold → rescue / normal boot -----
if boot_fail >= 3 and _G.gw_ota.active() ~= "-" then
  ota_remove(); boot_fail = 0; clear_boot()
  log.error("main", "ota reverted after 3 failed boots")
end
-- ---- signed SMS commands ----------------------------------------------------
-- The break-glass channel: the only way in when the Worker or the domain cannot be reached
-- at all, and it lives here, in the layer that is never updated over the air, so that it
-- still works with gw.lua broken or absent (rescue mode).
--
-- One SMS, ASCII, "<body> <mac>": body is the command (#status, #reboot, #url …, #ota …)
-- and mac is the FIRST 16 hex chars of HMAC-SHA256("sms\n" .. body) under SMS_KEY — the key
-- config.lua already carries and the same key the web's `ota`/`bases` buttons sign with. No
-- phone number is configured and no number is trusted: a caller ID is trivially spoofable,
-- a MAC is not. 16 hex = 64 bits, and a forgery costs one SMS per guess against a device
-- that answers slowly, so the short tag is ample; a variable-length mac is NOT accepted.
--
-- Anything that does not verify — no mac, a wrong mac, a mac for a different body, a `#`
-- from anyone at all — is forwarded as an ordinary SMS and never answered: the probe shows
-- up on the web page instead of turning the module into an oracle (and costs no SMS).
--
-- Replay is accepted and deliberate: a captured command can be resent, so it can only
-- re-apply something the owner once authorised. A replayed `#url` is further blunted by the
-- commit-confirm above (a since-dead domain is dropped again within ~20–30 min). That is
-- the same residual the web `bases`/`ota` signatures carry.
_G.gw_status_line = nil   -- only the gw.lua of THIS boot may install the rich #status line

-- The ONE canonical form, matched byte-for-byte by luatos/sms-sign.sh: trim the whole
-- message, split off the last whitespace-separated token as the mac, trim what is left.
-- Sign exactly the bytes that are compared.
local function sms_split(txt)
  local s = txt:gsub("^%s+", ""):gsub("%s+$", "")
  local body, mac = s:match("^(.-)%s+(%S+)$")
  if not body then return nil end
  return (body:gsub("^%s+", ""):gsub("%s+$", "")), mac
end
-- Fixed length, fixed alphabet, no early exit: a wrong guess leaks nothing but "wrong".
local function mac_eq(want, got)
  if #want ~= 16 or #got ~= 16 then return false end
  local diff = 0
  for i = 1, 16 do diff = diff | (want:byte(i) ~ got:byte(i)) end
  return diff == 0
end
local function sms_signed(body, mac)
  if type(mac) ~= "string" or #mac ~= 16 or not mac:match("^%x+$") then return false end
  local key32 = key32_of(merged())
  if not key32 then return false end   -- no key: nothing can validate, everything is forwarded
  local ok, full = pcall(crypto.hmac_sha256, "sms\n" .. body, key32)
  if not (ok and type(full) == "string" and #full >= 16) then return false end
  return mac_eq(full:sub(1, 16):lower(), mac:lower())
end
-- gw.lua publishes the rich line (queue depth, trust, signal — main.lua can see none of it)
-- as _G.gw_status_line. Without it (rescue mode, or gw.lua died before it got that far)
-- answer with what this layer knows by itself.
local function status_text()
  if type(_G.gw_status_line) == "function" then
    local ok, line = pcall(_G.gw_status_line)
    if ok and type(line) == "string" and line ~= "" then return line end
  end
  local fok, fw = pcall(rtos.version)
  return string.format("RESCUE boot_fail=%d ota=%s fw=%s ver=%s dev=%s",
    tonumber(kv_get("boot_fail")) or boot_fail, _G.gw_ota.active(), fok and tostring(fw) or "-", VERSION, dev_id)
end
-- → true when the message was a valid signed command: it has been executed and must NOT be
-- forwarded. Everything else returns false and travels on to the app's handler.
local function sms_cmd(num, txt)
  local body, mac = sms_split(txt)
  if not body or body:sub(1, 1) ~= "#" then return false end
  if not sms_signed(body, mac) then
    log.warn("main", "unsigned or wrongly signed # message from", num, "- forwarding it")
    return false
  end
  local cmd, rest = body:match("^#(%a+)%s*(.-)%s*$")
  if not cmd then log.warn("main", "signed but unparsable command", body, "- forwarding it"); return false end
  cmd = cmd:lower()
  log.info("main", "sms cmd", cmd, rest)
  if cmd == "status" then
    reply(num, status_text())
  elseif cmd == "reboot" then
    clear_boot(); rtos.reboot()                              -- deliberate: not a failed boot
  elseif cmd == "url" and rest:lower() == "reset" then
    bases_forget(); clear_boot(); rtos.reboot()              -- drops the override AND both markers
  elseif cmd == "url" then
    local ok, d = url_cmd(rest)
    reply(num, ok and "url ok rebooting" or ("url fail: " .. d))
  elseif cmd == "ota" and rest:lower() == "clear" then
    _G.gw_ota.clear(num)
  elseif cmd == "ota" then
    local name, hmac_hex = rest:match("^(%S+)%s+(%S+)$")
    if name then _G.gw_ota.install(name, hmac_hex, num) else reply(num, OTA_USAGE) end
  else
    -- Not one of ours: hand it on rather than swallow it. main.lua owns the SMS callback for
    -- good, so a command claimed here can NEVER reach an OTA gw.lua — and this file can never
    -- be updated. Returning false is the only thing that leaves room for a future gw.lua to add
    -- signed commands of its own (it verifies the same way: sms_split + HMAC over "sms\\n"..body,
    -- first 16 hex, case-insensitive). Without this, the signed-SMS surface is frozen forever.
    log.warn("main", "unknown sms command", cmd, "- forwarding it")
    return false
  end
  return true
end

-- main.lua owns the real SMS callback for good: every inbound message is offered to
-- sms_cmd first, and only what it did not claim reaches the app's handler. So an OTA
-- gw.lua that starts but never serves SMS — or never starts at all — cannot cut the
-- owner off from the module.
-- `sms` is a rotable userdata on stock firmware (luat_newlib2 → rotable2_newlib;
-- its metatable has __index but NO __newindex), so `sms.setNewSmsCb = ...` would
-- raise in the main chunk and brick every boot. Shadow the global with a plain
-- proxy table instead — a write to _G, which is a real table — and let __index
-- forward sms.send/autoLong/… to the library object untouched.
local app_cb
local real_sms = sms
_G.sms = setmetatable({ setNewSmsCb = function(fn) app_cb = fn end },
                      { __index = real_sms })
real_sms.setNewSmsCb(function(num, txt, metas)
  num, txt = tostring(num == nil and "" or num), tostring(txt == nil and "" or txt)
  local ok, handled = pcall(sms_cmd, num, txt)
  if not ok then log.error("main", "sms cmd", handled) end
  if ok and handled then return end
  if app_cb then
    local aok, err = pcall(app_cb, num, txt, metas)
    if not aok then log.error("main", "sms cb", err) end
  end
end)

if not key32_of(merged()) then
  -- No usable SMS_KEY: nothing can be encrypted, not even the registration — and no SMS
  -- command can be verified either, so every message is simply forwarded (nowhere, since
  -- gw.lua never starts). Say so, loudly, and do nothing else.
  _G.GCM_OK = false
  local function nag() log.error("main", "config.lua missing/invalid (SMS_KEY must be 64 hex): nothing will run") end
  nag(); sys.timerLoopStart(nag, 60000)
  sys.run()
  return
end

if boot_fail >= 3 then
  -- Flashed app cannot boot: no gw, no uploads, no SMS forwarding. Register once (so the web
  -- card shows boot= and ota=), poll every 60 s and run the web's reboot/bases/ota through
  -- gw_cmd — the OTA repair path. Everything pcall'd; a failure never stops the loop.
  rescue_mode = true
  log.error("main", "RESCUE MODE boot_fail=" .. boot_fail)
  local bases = split_bases(merged().BASES)
  local function first_2xx(method, path, ctype, body, timeout)   -- → code, body, base
    for _, b in ipairs(bases) do
      local code, rb = req(method, b .. path, hdr(ctype), body, timeout)
      if code >= 200 and code < 300 then return code, rb, b end
    end
    return -1, ""
  end
  local function rescue_poll()
    local code, body, base = first_2xx("GET", "/api/poll?dev=" .. dev_id, nil, nil, 15000)
    if code ~= 200 then log.warn("main", "rescue: poll failed", code); return end
    local ok, t = pcall(json.decode, body)
    if not ok or type(t) ~= "table" or type(t.status) ~= "string" then return end
    -- Only now: our Worker answered (a JSON status object), not just any 200 — a parked-domain
    -- landing page or captive portal answers 200 too, and this call confirms the bases override.
    _G.gw_alive()
    log.info("main", "rescue: poll", t.status)
    local cmd = t.status == "trusted" and type(t.cmd) == "table" and t.cmd or nil
    local id = cmd and tonumber(cmd.id)
    id = id and math.tointeger(id)
    if not id then return end
    local okr, detail = _G.gw_cmd.run(cmd, base)
    req("POST", base .. "/api/cmd/ack?dev=" .. dev_id, hdr("application/json"),
      string.format('{"id":%d,"ok":%s,"detail":"%s"}', id, okr and "true" or "false", jesc(detail)), 15000)
  end
  sys.taskInit(function()
    sys.waitUntil("IP_READY", 30000)
    -- The seal gets its OWN pcall. Sharing one with the POST is exactly how a board flashed
    -- without gcm.lua went invisible for good: load_module("gcm") threw, so the register was
    -- never sent, and rescue registers only once per session. No devices row means /api/poll
    -- and /api/ota/get both answer 403 — the web shows nothing, no command can be queued, and
    -- even a signed "#ota" cannot help, because the download needs that same row. An empty body
    -- still creates the pending row (the Worker stores info as NULL), which is all the web needs
    -- to show a card and let the owner push an OTA. Never fall back to an UNSEALED gw_reg: that
    -- would put IMEI/ICCID/IMSI on the wire in clear, with certificate verification off.
    local body = ""
    local sok, v1 = pcall(function()
      local gcm = _G.load_module("gcm")
      return gcm.seal(key32_of(merged()), _G.gw_reg("SIM 1", ""))
    end)
    if sok and type(v1) == "string" and #v1 > 0 then body = v1
    else log.error("main", "rescue: seal unavailable — registering with an empty body", v1) end
    local ok, err = pcall(function()
      local code = first_2xx("POST", "/api/register?dev=" .. dev_id, "text/plain; charset=utf-8",
        body, 15000)
      log.info("main", "rescue: register", code, #body)
    end)
    if not ok then log.error("main", "rescue: register error", err) end
    while true do
      ok, err = pcall(rescue_poll)
      if not ok then log.error("main", "rescue: poll error", err) end
      sys.wait(RESCUE_POLL_MS)
    end
  end)
  sys.run()
  return
end

local ok, err = pcall(function() _G.load_module("gw").start(merged()) end)
if not ok then
  log.error("main", "gw start failed:", err)
  sys.timerStart(rtos.reboot, 5000)   -- counted as a failed boot by the counter above
end
sys.run()
