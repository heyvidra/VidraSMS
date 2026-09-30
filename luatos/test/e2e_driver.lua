-- e2e_driver.lua — boots the REAL main.lua under fake_luatos.lua against the
-- local wrangler dev server, one power-on per invocation. Called by e2e.sh,
-- which drives the Worker side (login cookie, trust/block, commands, the OTA
-- upload) and inspects D1 out-of-band. Real curl HTTP (no http_mock), so
-- register/poll/upload/ack/OTA download actually hit http://127.0.0.1:8787.
--
--   lua e2e_driver.lua [label]
--
-- Env (all optional except the first three):
--   E2E_CONFDIR   dir holding the test config.lua (prepended to package.path)
--   E2E_FSKV      file that persists fskv across runs (identity, queue, ring, boot counter…)
--   FAKE_FS_ROOT  the /ota_*.lua sandbox dir (survives runs like the module's flash)
--   E2E_TICK      virtual ms to run the scenario before the health tick (default 8000)
--   E2E_SMS_FROM / E2E_SMS_TEXT [/ E2E_SMS_AT ms]   inject one inbound SMS
--   E2E_CALL=1    inject one INCOMINGCALL (a missed call) at t=0
--   E2E_AT_MS + E2E_AT_CMD   run a shell command at that virtual time (e.g. block the device on the web)
--   E2E_VERBOSE=1 unmute the logs
-- After the scenario the device keeps running until main.lua's health rule has
-- had its say (5 min up + one tick): BOOT_FAIL then shows 0 only if the Worker
-- answered a poll — the same rule the module lives by. A reboot ends the run early.
-- Output: KEY=VALUE lines + one "SEND\t<to>\t<body>" line per recorded sms.send.

local here = debug.getinfo(1, "S").source:match("^@(.*)/[^/]*$") or "."
package.path = here .. "/?.lua;" .. here .. "/../?.lua;" .. package.path
local confdir = os.getenv("E2E_CONFDIR")

local fake = require("fake_luatos")
-- Load the harness's config EXPLICITLY rather than leaving it to package.path. Relying on the
-- path let a real luatos/config.lua shadow the throwaway one (fake_luatos prepends luatos/ to
-- the path after we do), so the module fell back to main.lua's baked-in production DEFAULTS and
-- a "local" run registered itself against the live Worker. preload beats the path, always.
if confdir then fake.config = assert(dofile(confdir .. "/config.lua")) end
fake.quiet = (os.getenv("E2E_VERBOSE") ~= "1")
fake.no_run = true            -- sys.run() returns; virtual time is driven below

local function env_ms(k, d) return tonumber(os.getenv(k) or "") or d end

-- Count what the module said to the Worker, without touching the HTTP path.
local regs, polls_ok, cmd_acks, last_ack, upload_403 = 0, 0, 0, "", 0
local real_request = http.request
http.request = function(method, url, headers, body, opts, ca)
  local r = real_request(method, url, headers, body, opts, ca)
  local code = r.wait()
  if url:find("/api/register?", 1, true) and code == 200 then regs = regs + 1 end
  if url:find("/api/poll?", 1, true) and code == 200 then polls_ok = polls_ok + 1 end
  if url:find("/api/cmd/ack", 1, true) then cmd_acks = cmd_acks + 1; last_ack = body or "" end
  if code == 403 and not url:find("/api/", 1, true) then upload_403 = upload_403 + 1 end
  return r
end

fake.reboot_cycle()           -- power-on: main.lua merges config, mints the identity, starts gw

if os.getenv("E2E_AT_CMD") then
  sys.timerStart(function() os.execute(os.getenv("E2E_AT_CMD")) end, env_ms("E2E_AT_MS", 2000))
end
if os.getenv("E2E_SMS_TEXT") then
  local from, text = os.getenv("E2E_SMS_FROM") or "10001", os.getenv("E2E_SMS_TEXT")
  local at = env_ms("E2E_SMS_AT", 0)
  if at > 0 then sys.timerStart(function() fake.sms_incoming(from, text) end, at)
  else fake.sms_incoming(from, text) end
end
if os.getenv("E2E_CALL") == "1" then fake.call_incoming("+8613800138000") end

fake.tick(env_ms("E2E_TICK", 8000))
if not fake.rebooted then fake.run(math.max(fake.now, 330000)) end   -- health rule: 5 min + one 30 s tick

local gw = package.loaded["gw"]
local s = gw and gw._state and gw._state() or { queue = {}, poll_fail = -1, polls = -1, trust = "-" }
io.write("BOOT_FAIL=" .. tostring(fskv.get("boot_fail")) .. "\n")
io.write("DEVID=" .. tostring(fskv.get("dev_id")) .. "\n")
io.write("TRUST=" .. tostring(s.trust) .. "\n")
io.write("QUEUE=" .. #s.queue .. "\n")
if s.queue[1] then
  io.write("QSEQ=" .. tostring(s.queue[1].seq) .. "\n")
  io.write("TRIES=" .. tostring(s.queue[1].tries) .. "\n")
end
io.write("POLLS=" .. polls_ok .. "\n")
io.write("POLL_FAIL=" .. tostring(s.poll_fail) .. "\n")
io.write("REGS=" .. regs .. "\n")
io.write("CMD_ACKS=" .. cmd_acks .. "\n")
io.write("LAST_ACK=" .. last_ack .. "\n")
io.write("UPLOAD_403=" .. upload_403 .. "\n")
io.write("OTA=" .. tostring(_G.gw_ota and _G.gw_ota.active()) .. "\n")
io.write("GW_TAG=" .. tostring(_G.GW_TAG) .. "\n")
io.write("REBOOTED=" .. tostring(fake.rebooted) .. "\n")
io.write("LAST_CMD=" .. tostring(fskv.get("last_cmd")) .. "\n")
io.write("LAST_CMD_RES=" .. tostring(fskv.get("last_cmd_res")) .. "\n")
io.write("BASES=" .. tostring(fskv.get("bases")) .. "\n")
io.write("SENT=" .. #fake.sms_sent .. "\n")
for _, m in ipairs(fake.sms_sent) do
  io.write("SEND\t" .. tostring(m.to) .. "\t" .. tostring(m.body) .. "\n")
end
os.exit(0)
