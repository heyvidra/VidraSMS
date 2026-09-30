# FIRST-BOOT — 第一次上电

Two audiences. **Part 1** is for the person holding the board; it is written to be
pasted into a chat verbatim and read by someone who has never seen a dev board.
**Part 2** is for the owner, remote, deciding what to do next from whatever came back.

Board: 合宙 Air780EHV **核心板** (not the 开发板 — different button/LED layout).
Firmware: `LuatOS-SoC_V2052_Air780EHV_101.soc`. Script: `smsgw` `2.2.0`.

刷对了的话，开机第一屏必须同时满足这两条（缺一条就是刷错了变体或版本）：

```
I/main LuatOS@Air780EHV base … bsp V2052 64bit
self_info 127:firmware[101] VOLTE fs 768kbyte script 512kbyte
```

`firmware[101]` 认变体、`VOLTE` 认电信短信能力、`768kbyte` 认分区。
之前那块板子刷的是 `firmware[108] VOLTE fs 1536kbyte`，两者只差一个 `tts` 库。

---

## Part 1 — 给朋友的操作说明（直接复制发给对方）

See the fenced block at the bottom of this file, or copy from here:

```text
麻烦帮个忙，大概五分钟，不用懂技术，照着做就行。

1. 把 SIM 卡按卡槽上印的方向推进去，推到"咔"一声。注意别插反。
2. 用一根能传数据的 Type-C 线（手机充电线那种），一头插板子，一头插 5V 2A 以上的手机充电器。不要插电脑、不要插排插上的 USB 口。
3. 板子上有个小拨动开关，拨到印着 ON 的那一边。
4. 按住板子上印着「开机」的按钮 2 秒，松手。
5. 板子上会亮一颗小红灯。这颗灯只代表"线通电了"，不代表成功，看到亮就行，别管它。
6. 把板子放在靠窗的地方，等 2 分钟。
7. 回我一句"好了"，我这边就能看到它有没有上线。

⚠️ 千万不要按印着 boot 的那个按钮，也不要按「复位」。只按「开机」。
要重启的话：拨到 OFF → 数五秒 → 拨回 ON → 再按住「开机」2 秒。

如果我回你说"没看到它上线"，再麻烦做下面这几步（需要一台 Win10 或 Win11 电脑；苹果电脑做不了，没有对应的软件）：

8. 在 D 盘根目录建一个文件夹，叫 Luatools（别放在很深的目录里）。
9. 下载 https://cdn18.luatos.com/files/exe/Luatools_v3.exe 放进这个文件夹，双击打开。杀毒软件拦截的话请放行，一定要放行。
10. 板子用数据线直接插电脑的 USB 口（别用扩展坞/USB HUB），开关保持在 ON。
11. 软件下方黑色的日志区，确认「4G模块USB打印」这个勾是打上的。
12. 点「重启模块」按钮，等 2 分钟，会有一堆字滚动出来。
13. 关掉软件，打开 D:\Luatools\log\ 文件夹，把名字以 trace_ 开头、时间最新的那个文件发给我。
（main_ 开头的那个是软件自己的日志，没用，别发。）
```

**Why it is shaped that way** (do not send this part):

- The 核心板 does **not** boot when power is applied — `PWRKEY` must be pulled low
  >1 s, and on this board that is the `开机` button; the schematic shows no 0 Ω
  auto-power-on strap. Plugging it in and walking away is the single most likely
  way this deployment silently fails.
- Step 5 exists only to stop them reporting the LED as success. The core board has
  exactly **one** LED, wired `+4V → 470 Ω → LED → GND`, upstream of the ON/OFF
  switch and connected to **no module pin**: vendor text is
  *"板载的 LED 灯演示的是 Type-C USB 供电是否正常，跟拨码开关没有关系"*.
  It is lit when the board is switched off, crashed, unregistered, or perfect.
- `boot` = USB download mode: a silent dead end with no computer attached.
  Vendor's own BOOT gesture is *"按下BOOT键然后短按重启键"*, so BOOT + any other
  key is exactly what must not happen.
- 5 V/2 A: vendor requires *"持续供电电流大于1A，瞬间供电电流大于2A"* at VBAT and
  names the failure — *"严重时会造成周期性的反复重启"*. A laptop port or hub is the
  documented case.
- Windows 10+ only: Luatools states *"此工具运行于win10及以上系统; 不支持 Mac和 Linux。"*
  **There is no documented macOS or Linux path** — no vendor build, and whether the
  EC7xx composite device enumerates as CDC/ACM there is not documented anywhere.
  Do not promise one. A Windows VM with USB passthrough is undocumented and unsupported.
- No USB driver install: *"780 所有型号 … 都不需要安装 USB 驱动"*.
- The 核心板 button silkscreen is `开机` / `boot` / `复位` per the vendor's board photo;
  the burn docs also call these 开机键/POW、BOOT键、重启键 — if the friend says they
  cannot find a button called 开机, that ambiguity is unresolved and they should send
  a photo of the board rather than guess.

---

## Part 2 — 判读表（机主用）

### 2.0 The four instruments, ranked by what they actually prove

| Instrument | Proves | Does **not** prove |
|---|---|---|
| Red LED on the board | The Type-C cable is delivering 5 V | Anything else — not power-switch position, not boot, not network |
| A card on the web page | The module reached a Worker base, and `main.lua` built a register blob | That SMS works (see 2.5) |
| Luatools `trace_*.txt` | Everything — this is the only complete instrument | — (but needs a Windows PC) |
| Signed `#status` SMS reply | Module is up **and** SMS works both ways | Needs SMS to work, which is the thing most likely broken on 电信 |

Order of use: **web card first** (costs the friend nothing), then `trace_*.txt`,
then `#status` — never `#status` first on a 电信 SIM.

### 2.1 Exact log strings (quoted from source, not paraphrased)

`/Users/sidym/Workspace/sms/luatos/gw.lua`:

| Line | Source |
|---|---|
| `boot smsgw 2.2.0 <rtos.version()> <rtos.bsp()>` | `gw.lua:723` `log.info("gw", "boot", _G.PROJECT, M.VERSION, ver, bsp)` |
| `gcm selftest ok` | `gw.lua:768` |
| `SMS_KEY must be 64 hex chars — uploads disabled` | `gw.lua:757` |
| `SMS_KEY is all zeros (unedited placeholder?) — uploads disabled` | `gw.lua:760` |
| `SMS_KEY invalid — uploads disabled` | `gw.lua:769` |
| `GCM SELF-TEST FAILED — uploads disabled` | `gw.lua:770` |
| `no device identity (main.lua mints it) — network disabled` | `gw.lua:747` |
| `device identity not in fskv — using main.lua's in-RAM copy` | `gw.lua:743` |
| `fskv.init returned false — flash persistence unavailable (dev_id/queue/done-ring will not survive a reboot)` | `gw.lua:729` |
| `no bases configured` | `gw.lua:773` |
| `network tasks not started (key/identity/bases)` | `gw.lua:794` |
| `started dev=<16 hex> bases <n> queue <n>` | `gw.lua:816` |
| `registered: <status>` | `gw.lua:577` |
| `register failed <code> <base>` | `gw.lua:582` |
| `poll failed <code> <base>` | `gw.lua:624` |
| `poll body is not a status object <base>` | `gw.lua:617` |
| `poll failed <n> times in a row; rebooting` | `gw.lua:629` |
| `trusted on the web` | `gw.lua:559` |
| `waiting for trust on the web (dev <id>)` | `gw.lua:561` |
| `blocked on the web: uploads and sends paused` | `gw.lua:560` |
| `upload refused (403): not trusted on the web; keeping the queue` | `gw.lua:416` |
| `queued <sender> #bytes <n> depth <n>` | `gw.lua:402` |
| `未注册网络 status=<n>` (in an outbox result) | `gw.lua:495` |

`/Users/sidym/Workspace/sms/luatos/main.lua`:

| Line | Source |
|---|---|
| `config.lua missing/invalid (SMS_KEY must be 64 hex): nothing will run` | `main.lua:555`, re-emitted every 60 s by `sys.timerLoopStart(nag, 60000)` |
| `TRNG unavailable: no device identity this boot — network disabled` | `main.lua:159` |
| `RESCUE MODE boot_fail=<n>` | `main.lua:566` |
| `rescue: register <code>` / `rescue: poll <status>` / `rescue: poll failed <code>` | `main.lua:598` / `583` / `577` |
| `gw start failed: <err>` | `main.lua:613`, then `sys.timerStart(rtos.reboot, 5000)` |
| `bases override unconfirmed, boot <n>/3` | `main.lua:250` |
| `bases override unconfirmed after 2 tries — reverted to the built-in domains` | `main.lua:245` |
| `ota reverted after 3 failed boots` | `main.lua:433` |
| `no poll answered in 15 min with OTA code active: failed boot, rebooting` | `main.lua:425` |

**Healthy ordering:** `boot smsgw 2.2.0 …` → `gcm selftest ok` → `started dev=… bases 2 queue 0`
→ `registered: pending` → (after 信任) `trusted on the web`.

**The one unmistakable shape:** a bad `SMS_KEY` returns from `main.lua` *before*
`gw.start` is ever called, so you get the `config.lua missing/invalid …` nag every
60 s and **no** `boot` / `selftest` / `started` line at all. That distinguishes
"flashed but misconfigured" from "did not boot" with certainty.

### 2.2 The `#status` reply fields

Signed with `bash luatos/sms-sign.sh '#status'`. Two possible shapes.

Normal (`gw.lua:665-667`, `status_line()` published as `_G.gw_status_line`):

```
2.2.0 csq=<n> net=<n> ip=<addr> q=<n> gcm=ok|FAIL fw=<rtos.version> trust=pending|trusted|blocked|? ota=<name|-> boot=<n> ws=up|down|off utc=<hh> win=fast|slow
```

| Field | Read it as |
|---|---|
| leading `2.2.0` | `M.VERSION` — the script version actually running |
| `csq=` | `mobile.csq()`; `-` means the call failed |
| `net=` | `mobile.status()`; this is the network-registration number |
| `ip=` | `socket.localIP()`; `-` = no data bearer |
| `q=` | upload queue depth — messages captured but not yet delivered to the Worker |
| `gcm=` | `ok` or `FAIL`; `FAIL` means uploads are disabled (bad key or broken crypto) |
| `fw=` | `rtos.version()` — confirms which `.soc` is on the module |
| `trust=` | the last `/api/poll` status: `pending` / `trusted` / `blocked` / `?` (never polled) |
| `ota=` | active OTA script names, `-` when running flashed code |
| `boot=` | `boot_fail` counter; `0` = last boot was confirmed healthy, `3` = rescue |

Fallback (`main.lua:490-492`, used when `_G.gw_status_line` is absent — rescue mode,
or `gw.lua` died before publishing it):

```
RESCUE boot_fail=<n> ota=<name|-> fw=<version> ver=2.2.0 dev=<16 hex>
```

Receiving the `RESCUE …` shape at all is itself the finding: `gw.lua` is not running.

### 2.3 Decision table — start from what was observed

| Observed | Means | Do |
|---|---|---|
| **Friend says "灯亮了、按了开机"; no card on the web after 10 min** | Ambiguous — this is the expensive case. Could be: never pressed 开机 properly, SIM in backwards, no coverage, bad `SMS_KEY`, brownout loop. Nothing external separates them. | Ask for the LED-only checks in 2.4 first (free). If they all pass, escalate to the Luatools path in Part 1 steps 8–13. |
| **Friend says the red LED never lit** | No 5 V at all: charge-only cable, dead charger, or the cable is not seated. The LED is upstream of the ON/OFF switch, so switch position cannot cause this. | Swap cable (one they have actually moved files with) and charger. Nothing else is worth trying. |
| **A card appears, badge `待信任`** | Best possible outcome. `main.lua` ran, `SMS_KEY` parsed, GCM sealed the register blob, the module reached a base and got a `status` back. `gw.lua:561` `waiting for trust on the web (dev <id>)`. | Click **信任** on the card. Then check the card's `boot=` and `ota=` fields and the online dot. Tell the friend "好了" and stop. |
| **Card appears, `boot=3`, and the card shows the rescue shape** | `main.lua:566` `RESCUE MODE boot_fail=3` — `gw.lua` failed to start three times. Rescue still registers and polls every 60 s and accepts web commands. | It is reachable: use the web command path (reboot / ota) rather than asking the friend for anything. Get the `trace_*.txt` to see the `gw start failed: <err>` text. |
| **Card appears, then goes 离线, then reappears with a new `dev=`** | Either `fskv` cannot persist (`gw.lua:743` / `:729`) or the module is reboot-looping. A new identity every boot is the deliberate visible symptom. | If it is reboot-looping: this is the vendor's named underpowered-supply failure — *"周期性的反复重启"*. Send a 5 V/2 A charger and a short data cable. If identity churns but uptime is fine, it is worn flash, not power. |
| **Card appears and stays 在线, but no SMS ever arrives** | See 2.5 — most likely 电信 VoLTE. `#status` will show a healthy `csq=` / `net=` / `ip=` and `q=0`. | Have someone send a real SMS to the number. If the log shows no `queued <sender> …` line, the module never received it. Then call 中国电信 about VoLTE 开通. |
| **No card ever, and friend can borrow a Windows PC** | — | Part 1 steps 8–13. Read the `trace_*.txt` against 2.1. |
| **`trace_*.txt` is empty** | In order of likelihood: `通用串口打印` ticked instead of **4G模块USB打印**; Luatools opened after boot (fix with **重启模块**); board is in BOOT mode (Device Manager shows exactly **1** port instead of 3–4 — vendor: *"如果出现了一个端口，则表示成功进入BOOT下载模式"*); another serial tool holding the port. | Walk through in that order. Only the BOOT-mode case needs the friend to touch the board (press `复位` alone, or OFF→ON). |
| **`trace_*.txt` shows `config.lua missing/invalid (SMS_KEY must be 64 hex): nothing will run` every 60 s, nothing else** | The seller flashed a `config.lua` whose `SMS_KEY` is not 64 hex. `main.lua:555`. Nothing else is wrong. | Needs a reflash of `config.lua` — which needs the Windows PC anyway. Do not chase network or SIM. |
| **`boot smsgw 2.2.0 …` present, `GCM SELF-TEST FAILED — uploads disabled`** | Crypto, not network. `gw.lua:770`. | Check the flashed firmware string on that same `boot` line against `LuatOS-SoC_V2052_Air780EHV_101.soc`. Wrong `.soc` is the first suspect. |
| **`started dev=… bases 2 queue 0` present, no `registered:` line, repeated `register failed <code> <base>`** | On the module side everything works; the Worker is not answering 2xx. The code tells you which: `-1` = no network/DNS, `403`/`404` = the device row was 忘记'd, `5xx` = Worker. | Read the code. `-1` with `ip=-` in `#status` means no bearer, which on a fresh 电信 SIM usually means no APN attach yet — leave it 10 more minutes before touching anything. |
| **`poll failed <n> times in a row; rebooting`** | `gw.lua:629`. Network outage or wrong bases. Note the counter is deliberately cleared unless an OTA copy is active, so this cannot walk a healthy module into rescue. | If it recurs with a good `csq=`, suspect the bases. `#url reset` (signed) drops any override. |
| **`bases override unconfirmed, boot <n>/3`** | Someone set a `bases` override that has never answered a poll. Self-heals: after 3 boots `main.lua:245` reverts to the built-ins. | Wait for the revert; it is designed for exactly this. |
| **Only a `RESCUE …` `#status` reply, nothing on the web** | SMS works but data does not. Unusual and informative: the module is registered on the network for SMS and `gw.lua` is not running. | The reply carries `dev=` — that is the device id to look for. Send `#reboot` (signed) and watch for the card. |

### 2.4 If the helper can do literally nothing but report the LED

This is the realistic worst case, and it is nearly blind. The LED answers one bit
only. Everything below is what can still be extracted by voice:

1. **"灯亮吗？"** — No: cable or charger. Yes: 5 V is present, nothing more.
2. **"开关拨到哪边？念一下上面印的字。"** — must be `ON`. The LED lights at `OFF` too,
   so this cannot be inferred.
3. **"按住那个印着『开机』的按钮两秒，松手。"** — have them do it again regardless of
   what they say they did. It is free and it is the likeliest single failure.
4. **"卡推进去的时候有咔一声吗？"** — a backwards or unseated nano-SIM is silent and invisible.
5. **"板子旁边有没有窗？能不能挪到窗边？"** — the on-board chip antenna is vendor-described
   as *"实际性能比较一般"*.
6. **"充电器上印的是 5V 几 A？"** — anything under 2 A is the documented reboot-loop risk.
   Note the LED draws only ~4 mA off the post-buck `+4V` rail, so a brownout deep
   enough to reset the module **will not visibly dim it** — the LED cannot report a
   reset loop. (That inference is mine, from the schematic; the vendor documents the
   loop but says to diagnose it from repeating boot logs, or with an oscilloscope —
   explicitly *"切记不能用万用表"*.)
7. If they happen to own a USB power meter, a repeating current pattern is the only
   no-computer signature of the reset loop. Inference, not vendor guidance.

After all six, the remaining unknowns are indistinguishable without the log. Do not
keep asking — escalate to borrowing a Windows PC, or to posting a second board.

### 2.5 The failure this table cannot catch

电信 SMS needs **two** things, and the device looks perfectly healthy without the second:

- Firmware with the `cc` (VoLTE) core library — **satisfied**: `_108` is the 64-bit
  build of variant 8, whose `sms` row is marked `✓支持电信` and which includes `cc`.
- **VoLTE 开通 on the SIM itself** — vendor: *"使用电信卡 SMS 短信功能时请务必选择同时支持
  CC(VoLTE通话)的固件版本并且需要电信卡开通 VoLTE 功能"*. **Unknown for this SIM.**

Without it the module will still attach for data, so `/api/register` and `/api/poll`
succeed, the web card goes 在线, and `#status` reports a healthy `csq=` / `net=` / `ip=` —
while SMS silently never arrives. Neither the LED, nor the card, nor the Worker
distinguishes it. That last sentence is inference; the two preconditions are vendor-documented.

**The only reliable test is end-to-end: have someone send a real SMS to that number
and watch for a `queued <sender> #bytes <n> depth <n>` line / a row on the web.**
Confirm VoLTE with 中国电信 before the board ships if at all possible.

### 2.6 Two things worth knowing before trusting the recovery paths

- `main.lua:55` `wdt.init(9000)` is very likely inert on this chip. Vendor: Air780 series
  has *"无软件看门狗，内部硬件看门狗由内核固件自动启动，不支持用户启动"*, timeout fixed at 28 s,
  and the kernel feeds it *"每隔一段时间自动喂一次狗"*. So a hung Lua task may **not** be
  rescued, and the boot-loop guard's premise does not clearly hold. Untested — do not
  rely on the watchdog to recover a remote board.
- `#status` and every other `#` command require SMS to work in **both** directions.
  On this SIM that is the least-proven link in the chain, so treat the SMS command
  channel as a bonus, not as the remote-management plan. The web command path
  (`_G.gw_cmd`, served through `/api/poll`) works over data and keeps working in
  rescue mode.
