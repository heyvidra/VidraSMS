CREATE TABLE IF NOT EXISTS messages (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts     INTEGER NOT NULL,  -- when the worker received it, epoch ms
  sender TEXT    NOT NULL,
  body   TEXT    NOT NULL
);

-- The page reads newest-first and polls with id > ?, so both go through this.
CREATE INDEX IF NOT EXISTS idx_messages_id_desc ON messages (id DESC);

-- Web Push subscriptions (iOS PWA etc). Data-less pushes only need the endpoint; the
-- keys are stored for completeness. INSERT OR REPLACE keyed on endpoint dedups re-subs.
CREATE TABLE IF NOT EXISTS subs (
  endpoint TEXT PRIMARY KEY,
  p256dh   TEXT,
  auth     TEXT
);

-- Outbound SMS queue. payload is the encrypted {to, body} (server never sees the number or
-- text in clear); the phone polls pending rows, sends, then acks. status: pending|sent|failed.
CREATE TABLE IF NOT EXISTS outbox (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  payload TEXT    NOT NULL,
  status  TEXT    NOT NULL DEFAULT 'pending',   -- pending -> sending (claimed) -> sent|failed
  detail  TEXT,
  -- Which phone may send this row. NULL = any of them. Without it two phones race for every
  -- send and the message can go out over the wrong SIM. Added to the live DB by ALTER TABLE;
  -- it must be here too or a fresh setup silently lacks the column and every claim 500s.
  dev     TEXT,
  -- How many times this row has been claimed. A phone on a weak/roaming signal can claim a send,
  -- fail to submit it, and never get its ack back — leaving the row cycling sending↔pending
  -- forever ("发送中" that never ends). After MAX_CLAIMS attempts the claim path marks it failed
  -- instead of re-queuing. Also ALTER-added to the live DB, so it must be here for fresh setups.
  claims  INTEGER NOT NULL DEFAULT 0
);

-- Tiny key/value bag. Currently just 'beat' = the phone's last poll time (epoch ms), which the
-- web reads to show whether the forwarding phone is still alive.
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT
);

-- One row per phone running the app. `ts` is its last poll (the heartbeat, per device now, so
-- two phones can't mask each other's outage). `info` is an encrypted {name, sims} blob — the
-- device's own name and SIM carriers are PII, so the server stores it opaque, exactly like a
-- message body. The id itself is a random opaque string with no meaning to the server.
CREATE TABLE IF NOT EXISTS devices (
  id     TEXT PRIMARY KEY,
  ts     INTEGER NOT NULL,
  info   TEXT,
  -- Self-registering modules (Air780EHV) present their own bearer secret; only sha256(secret) is
  -- kept, so a D1 dump never yields a usable credential. Phones use the global SEND_TOKEN and
  -- have auth NULL. Both columns are ALTER-added to the live DB by setup.sh; they must be here
  -- too or a fresh setup silently lacks them and /api/register 500s.
  auth   TEXT,
  -- pending | trusted | blocked. A module starts 'pending' and may only publish/poll once the
  -- web trusts it; phones default to 'trusted' and the legacy token ignores this column anyway.
  status TEXT    NOT NULL DEFAULT 'trusted'
);

-- Web deletes that must be mirrored onto the phones. When a message is deleted on the web, its
-- encrypted body is copied here; each phone reads rows past its stored high-water mark on the next
-- poll, decrypts, and deletes the matching SMS from the system SMS database (only the default-SMS
-- app phone actually holds a copy). Broadcast to all phones; pruned after a week by scheduled().
CREATE TABLE IF NOT EXISTS deletions (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  payload TEXT    NOT NULL   -- the deleted message's encrypted body (v1:...)
);

-- Web → module commands, picked up on the module's normal poll (one pending per device). The
-- payload is plaintext JSON on purpose: {"type":"reboot"} | {"type":"ota","name":"gw","hmac":..}
-- | {"type":"bases","value":"https://a,https://b"} — none of it is PII, and the server needs to
-- read nothing from it. An OTA script itself is signed in the browser with SMS_KEY (the hmac),
-- which the server never holds, so a compromised Worker cannot push code to a module.
CREATE TABLE IF NOT EXISTS cmds (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  dev     TEXT    NOT NULL,
  payload TEXT    NOT NULL,
  status  TEXT    NOT NULL DEFAULT 'pending',   -- pending | done | failed
  detail  TEXT
);

-- Every poll asks "is there a pending cmd for me", and /api/cmd asks the same before inserting.
CREATE INDEX IF NOT EXISTS idx_cmds_dev_status ON cmds (dev, status);
