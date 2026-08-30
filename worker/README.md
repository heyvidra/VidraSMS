# SMS → Cloudflare Worker

手机收到短信 → 安卓 app 用 HTTPS + token 上报 → Cloudflare Worker 存进 D1 → 浏览器打开网页看。

没有服务器要维护，不用信用卡，免费额度用不完。

```
[SIM 手机: SmsForward app] --HTTPS+token--> [Cloudflare Worker + D1] --浏览器--> [你]
```

**本项目使用的域名：`777310753.xyz`**（NameSilo 注册，$0.99/年，注册与续费同价）

## ✅ 已在生产环境实测通过（2026-08-27）

真域名、真证书、真 Worker、真 D1，无任何测试脚手架：

| 场景 | 结果 |
|---|---|
| 中文验证码短信 | 原样送达，发件人正确 |
| 超长多段短信 | 560 字（约 9 段）完整拼接 |
| **断网期间收到短信** | 排队不丢，恢复网络 **11 秒**内自动补发 |
| 网页端 | 未登录 401 弹框，登录后消息列表正常显示 |
| 错误 token / 错误 topic | 403 / 404，手机端会弹「转发失败」通知 |

> **⚠️ 唯一的长期风险：域名忘记续费。** 到期后整套转发会静默失效，而你多半是在
> 急着收验证码时才发现。**建议在 NameSilo 打开 Auto-Renewal**（$0.99/年）。
> 当前到期日：2027-08-27。

---

## ⚠️ 为什么必须绑自己的域名

**`*.workers.dev` 在中国大陆被 DNS 污染，基本连不上** —— OONI 在 2025-01 至 2026-08 的
205 次测量中有 202 次异常。这不是慢，是解析不到。所以"零配置直接用 workers.dev"走不通。

绑自有域名后 Cloudflare 自动配 DNS 和证书，Workers 这边不额外收费。

> 次要风险：社区报告 GFW 曾批量封锁部分 Cloudflare anycast IP（例如以 `.1` 结尾的
> `104.21.x.1`），绑了自有域名仍可能运气不好落到被封的 IP 上。这属于社区观测、无官方确认，
> 不像 workers.dev 那样是确定性的。真遇上了 Cloudflare 的 anycast IP 你换不了 ——
> 这是相比自建 VPS（可一键换 IP）的一个真实劣势。

---

## 1. 把域名接到 Cloudflare

因为是**全新注册、没有任何解析记录**的域名，这一步几乎零风险 ——
没有 DNSSEC 要关，没有邮箱会挂，没有记录要搬。

1. 注册 Cloudflare 账号（**只要邮箱 + 密码，不需要信用卡**）。
2. 控制台 → Add a domain → 填 `777310753.xyz` → 选 **Free** 套餐。
3. Cloudflare 会给你两个 nameserver，形如 `xxx.ns.cloudflare.com`，记下来。
4. 登录 NameSilo → Domain Manager → 选中域名 → **Change Nameservers**，
   把默认的 `NS1/NS2/NS3.DNSOWL.COM` **全部替换**成 Cloudflare 给的两个。
   > 必须替换，不能追加。留着 NameSilo 的 NS 会让 Cloudflare 一直卡在 Pending。
5. 等 Cloudflare 状态变成 **Active**（通常几分钟到一小时）。用这个命令自查：

```bash
./check-dns.sh 777310753.xyz
```

NS 那一栏出现 `ns.cloudflare.com` 就成了。

> 新域名前几分钟可能查不到任何记录，属正常，等一会儿再试。

---

## 2. 部署

**前置：** Node.js、Cloudflare 账号、上一步的 zone 已经是 Active。

```bash
cd worker
./setup.sh
```

脚本会：登录 → 建 D1 数据库 → 建表 → 生成手机端 token → 让你设网页登录的用户名密码 →
部署并**自动绑定 `777310753.xyz`**，最后打印要填进 `android/local.properties` 的三行。
可重复执行。

> **如果 `wrangler login` 卡住**：它要开浏览器走 OAuth，而 Cloudflare 控制台从国内访问
> 常常极慢（有报告登录页要 40 秒以上）。卡住就改用 API token：
> 控制台 → My Profile → API Tokens → Create Token → 用 **Edit Cloudflare Workers** 模板，
> 然后 `export CLOUDFLARE_API_TOKEN=xxx` 再跑 `./setup.sh`，全程不需要浏览器。

自定义域名写在 `wrangler.toml` 的 `routes` 里，所以不需要去控制台手动点 ——
但前提是 zone 必须已经 Active，否则部署会失败。

改动代码后重新部署：

```bash
npx wrangler deploy
```

---

## 2.5 让手机直接下载安装（777310753.xyz/app）

签名 release APK 存在 Cloudflare KV 里，浏览器打开 **`https://777310753.xyz/app`**，
输入**下载码**即可下载安装（`/c.apk` 同一个）。换新版本后重传一条命令，无需重新部署 Worker：

```bash
cd android && ./gradlew assembleRelease      # 出新 APK
cd ../worker && ./upload-apk.sh              # 传到 KV
```

**下载码**存在 `worker/.apk_code`（已 gitignore）。想改：

```bash
cd worker && echo "你的新码" | npx wrangler secret put APK_CODE
```

> APK 里编译进了 `NTFY_TOKEN` 和 `SMS_KEY`，下载码这道门就是防随手拿到 URL 的人反编译取走它们。
> 码在服务端校验（`APK_CODE` secret），不写进前端；错码有 600ms 延迟拖慢暴力猜。

## 2.8 iPhone 推送通知（PWA）

iOS 上任何浏览器都是 WebKit，普通网页收不到通知 —— 唯一的办法是把网页**用 Safari 添加到主屏幕**
变成 PWA，才能收 Web Push。已经配好了，你在 iPhone 上这样开：

1. **用 Safari**（不是 Chrome）打开 `https://777310753.xyz`，登录。
2. 点底部**分享**按钮 → **添加到主屏幕**。桌面会出现「验证码」图标（蓝紫 C）。
3. 从**主屏幕图标**进入（不是从 Safari 标签），点右上角**「通知」**→ 允许。
4. 之后一来短信，锁屏就会弹「新验证码 · 点击查看」，点开 App 看解密后的内容。

**为什么通知里没有验证码内容**：服务器上只有密文（它不知道验证码是什么），所以推送只能是
通用提示，点开 PWA 才本地解密显示 —— 这反而保证内容不经过苹果的推送服务器。

技术上：无内容 Web Push + VAPID 签名；订阅存在 D1 的 `subs` 表；服务端每来一条短信就
`ctx.waitUntil` 推给所有订阅（过期订阅自动清理）。安卓 Chrome / 桌面浏览器同样点「通知」即可，
无需装 PWA。

> **注：iOS 端到端投递我无法在这里实测**（需要真机）。VAPID 签名算法、各端点、Service Worker、
> manifest 都已验证。若在 iPhone 上开不起来，把点「通知」后的报错发我，我按反馈调。

## 3. 安卓端不用改代码

Worker 故意做成接受和之前完全一样的请求（`POST /<topic>`、`Authorization: Bearer`、
`Title` 头放发件人），所以 app 一行都不用动，只要改 `local.properties`：

```
NTFY_URL=https://777310753.xyz
NTFY_TOPIC=sms-7f3a9c2b1e0d
NTFY_TOKEN=tk_xxxxxxxx
```

然后重新编译安装，**在手机上打开一次 app**（新安装的应用处于 stopped 状态，
不打开收不到短信广播 —— 详见 [根目录 README](../README.md) 的警告）。

`NTFY_TOPIC` 必须和 `wrangler.toml` 里的 `TOPIC` 一致 —— 不一致会返回 404，
手机上会弹「转发失败」通知，不会静默丢失。

---

## 4. 端到端加密（服务器看不到内容）

短信在**手机上就加密**（AES-256-GCM，每条随机 IV），Cloudflare 只存密文。
**发件人也在密文里**，所以服务器连「这是哪家银行发的」都推断不出来 —— D1 里的
`sender` 一律是 `unknown`。

密钥 `SMS_KEY` 只存在两个地方：手机的 `local.properties` 和浏览器的 localStorage，
**从不上传**。`setup.sh` 会生成它并存到 `worker/.sms_key`（已 gitignore）。

```bash
cat worker/.sms_key    # 查看你的密钥
```

> **⚠️ 这串丢了，已存的消息就永远解不开。** 服务器上没有备份 —— 这是端到端加密的
> 代价，不是 bug。**请存进密码管理器。**

**浏览器端每台设备填一次即可**：打开页面 → 右上角「密钥」→ 粘贴 → 保存。
密钥存在 localStorage，**退出登录、重启浏览器都不会清掉**；只有换设备、用无痕窗口、
或手动点「清除」才需要重填。

没填密钥时页面会显示「🔒 已加密 / 无法解密」并指引你去填，不会显示乱码。
加密上线之前的老消息仍按明文正常显示。

## 5. 看短信

浏览器打开 `https://777310753.xyz`，用 `setup.sh` 时设的用户名密码登录。

- 登录状态保持 **30 天**，右上角有「退出」按钮。
- 新短信会自己出现，**不用刷新**（页面每 10 秒轮询一次）。
- 标签标题会变成 `(1) 短信` 这样的未读计数，**把页面固定在标签栏**，余光就能看到。
- **验证码会高亮，点一下复制**（复制被浏览器拒绝时自动选中，可直接 Cmd+C）。
- **鼠标悬停消息出现 ✕，点击删除**（手机上常驻显示）。
- 支持暗色模式，跟随系统。

### 改用户名 / 密码

```bash
cd worker
npx wrangler secret put WEB_USER    # 或 WEB_PASS
```

**改任一项都会立刻踢掉所有已登录设备** —— 用户名和密码都参与会话签名。
改完需要重新登录，但**解密密钥不受影响，不用重填**。

> 后台标签会被浏览器自动降频到约每分钟一次，所以挂着不费额度。

### 登录的安全设计

会话 cookie 用 **HMAC-SHA256** 签名，过期时间签在 payload 内（客户端改不了），
带 `HttpOnly` + `Secure` + `SameSite=Strict`。

**密码是签名密钥的一部分**，所以改 `WEB_PASS` 会让所有旧会话立即失效 ——
不需要维护任何会话存储。`SESSION_SECRET` 由 `setup.sh` 随机生成，你不用记；
想强制所有设备重新登录，删掉这个 secret 重跑 `setup.sh` 即可。

转发和网页是两套独立鉴权：手机用 `SEND_TOKEN`，浏览器用 cookie，互不通用
（拿浏览器 cookie 去发短信会 403）。

> **换过来之后第一次访问，浏览器可能仍弹旧的 Basic auth 框** —— 那是 Chrome
> 按源缓存了旧凭据。用无痕窗口验证，或 `Cmd+Shift+R` 硬刷新 / 重启浏览器即可。

---

## 额度与费用

| 项目 | 免费额度 | 你的用量 |
|---|---|---|
| Worker 请求 | 100,000 次/天 | 每天几十条短信 + 网页轮询，挂一个后台标签约 1,400 次/天 |
| D1 写入 | 100,000 行/天 | 每条短信 1 行 |
| D1 读取 | 5,000,000 行/天 | 每次轮询几行 |
| D1 存储 | 5 GB（单库 500 MB） | 一条短信约 200 字节 |

**超额是直接报错，不会自动扣钱** —— Workers 付费版要主动订阅，没绑卡就没有扣款途径。

域名续费 $0.99/年（数字 .xyz 的「1.111B」价，注册续费同价，不是首年促销）。
**这是整套方案唯一的固定支出。**

## 数据

消息全部留存，不自动删除（500 MB 够放上百万条）。Cloudflare 条款声明账号终止后
只保留 30 天访问，所以**别把 D1 当唯一副本**，偶尔导出一次：

```bash
npx wrangler d1 execute sms --remote --command "SELECT * FROM messages" --json > backup.json
```

---

## 附：如果哪天想改用已有域名（如 GoDaddy 上那个）

把一个**在用**的域名搬到 Cloudflare 风险高得多，两个坑会让域名整个打不开：

- **DNSSEC**：必须先在原注册商关掉，**再等 24–36 小时**才能改 NS。
  `.com` 的 DS 记录 TTL 是 86400 秒；原注册商说的「90 分钟」指的是他们自己后台刷新，
  跟全球解析器缓存无关。没等够就改 NS，开启校验的解析器全部返回 SERVFAIL。
  确认 DS 真的没了：`dig +norec DS 你的域名 @a.gtld-servers.net`（ANSWER 为空才行）。
- **邮箱**：搬 NS 是全有或全无，没在 Cloudflare 重建的记录立刻失效。
  Cloudflare 官方明说自动扫描「不保证找全」——它靠猜名字去查，结构上找不到
  DKIM 的 `selector1._domainkey` 这类记录。正确做法是原注册商导出 Zone File 再导入。
  邮箱挂掉还特别阴：发信方重试 24–72 小时才退信，你可能几天后才发现。

另外，**免费版不能只委托一个子域名**（子域名委托是企业版专属，CNAME 部分接入要
Business 版），所以只能整个域名搬。改完后 48–72 小时内不要动原注册商那边的记录，
`.com` 的委托 NS 缓存 TTL 是 172800 秒（48 小时）。

搬之前和搬之后各跑一次 `./check-dns.sh 你的域名`，diff 一下，**消失的记录就是要出问题的服务**。
