# 短信转发（自用）

手机收到短信 → Android app 用 HTTPS + token 上报 → 后端存下来 → 浏览器打开网页看。

```
[SIM 手机: SmsForward app] --HTTPS+token--> [后端] --浏览器--> [你]
```

**当前方案：Cloudflare Worker + D1** → 见 **[worker/README.md](worker/README.md)**

不用服务器、不用信用卡、免费额度用不完。
安卓端代码不用改，只改 `local.properties` 里的地址。

- **[android/](android/)** —— 发送端（这部分两种方案通用）
- **[worker/](worker/)** —— Cloudflare Worker 后端（当前方案）
- **[server/](server/)** —— 自建 VPS + ntfy 后端（备选方案，已完整实现并测试过）
- **[check-dns.sh](check-dns.sh)** —— 搬域名前后各跑一次，diff 一下就知道有没有搞挂邮箱

> **域名：`777310753.xyz`**（NameSilo，$0.99/年，注册续费同价）。
> 两个方案都需要自有域名 —— Worker 方案是因为 `*.workers.dev` 在国内被 DNS 污染，
> VPS 方案是因为要签 TLS 证书。

下面是**备选方案（自建 VPS + ntfy）**的文档。只用 Worker 方案的话，看
[worker/README.md](worker/README.md) 加下面的「3. Android 端」一节就够了。

---

## 0. 机器放哪（2026-08 实查）

**结论：Oracle Always Free 的 AMD 小机器（E2.1.Micro），区域选首尔或东京。**

几个查证过的要点，按重要性排：

- **⚠️ 空闲回收会打中这个用途。** Oracle 规定：连续 7 天 CPU（95 分位）、网络、内存三项都低于 20% 的
  Always Free 实例会被**停机**。一台每天转发几十条短信的 ntfy 完全符合这个画像。
  **解法：把账号升级成 Pay As You Go（PAYG）** —— Oracle 自己的通知邮件写明升级后不再回收，
  且只要用量不超 Always Free 额度就**不收费**。升级前在控制台设一个 $1 的预算告警兜底。
- **首页区域（home region）选定后不可更改**，且 Always Free 的计算和块存储只能开在首页区域。
  国内访问延迟社区普遍推首尔（三网直连）、其次东京/新加坡 —— 属经验之谈，无官方数据。
- **用 AMD E2.1.Micro，别去抢 ARM。** A1 的免费额度已于 2026-06-15 从 4 OCPU/24GB
  悄悄砍半到 2 OCPU/12GB，并从 2026-08-18 起清理超额实例；而且 A1 长期"out of host capacity"。
  E2.1.Micro（1/8 OCPU、1GB 内存、可开 2 台）额度未变、随时能开，跑 ntfy + Caddy 绰绰有余。
- **ping 不通不等于被墙。** Oracle 默认安全列表不放行 ICMP，从哪儿都 ping 不通。
  判断可达性请用 TCP（`curl -I https://你的域名` 或 telnet 443）。
- 免费额度含 10TB/月出站流量，这个用途连零头都用不到。

**其他方案为什么没选：**

| 方案 | 结论 |
|---|---|
| 阿里云国际站 | **没有永久免费的服务器**。ECS 是 $90 代金券管 3 个月；之后最低约 $4/月（香港轻量）。 |
| 阿里云大陆 | 域名解析到大陆服务器**必须备案**，阿里云会在服务商层面直接封 80/443，换非标端口也明确不豁免。 |
| Cloudflare | **不卖虚拟机**。Containers 要 $5/月且会自动休眠，跑不了常驻服务。 |
| GCP e2-micro | 永久免费，但**公网 IPv4 要另收约 $3.65/月**，且只有美国区域，延迟差。 |
| AWS / Azure | 都没有永久免费的机器，只有 6～12 个月试用。 |
| Fly.io / Render | Fly 已无免费层；Render 免费服务闲置 15 分钟即休眠，不适合。 |

> 如果哪天不想折腾 Oracle：RackNerd 年付约 $1/月、Vultr $2.5/月起，花小钱换省心也很合理。

## 0.5 开通 Oracle 账号（你本人操作，约 15 分钟）

**开始前先备好：**
- 一张**真实信用卡**，或带 Visa / Mastercard 标志的借记卡。预付卡、虚拟卡、单次卡会被拒。
  卡不会被扣款，只做一笔约 $1 的临时授权，几天后自动释放。
- 能收国际短信的手机号、一个邮箱。

**步骤：**

1. 打开 `https://www.oracle.com/cloud/free/`，点 Start for free。
2. 填邮箱 → 收验证邮件 → 填姓名、地址、手机号 → 收短信验证码。
3. **选 Home Region —— 这一步选完永久不能改。** 建议 **South Korea Central (Seoul)**，
   国内三网直连、延迟最低；备选 Japan East (Tokyo)、Singapore。
   选错了只能销毁整个租户重来（30 天且不可逆），所以别手滑。
4. 填卡 → 同意条款 → 提交。等待开通邮件（通常几分钟，偶尔要几小时）。
5. 登录控制台后，**立刻做两件事**：
   - 右上角账号菜单 → **Upgrade to Pay As You Go**（防止机器被当闲置停掉，见上一节）。
   - Billing → Budgets → 建一个 **$1** 的预算告警兜底。

**接着开机器：** Compute → Instances → Create Instance
- Image：**Ubuntu 24.04**
- Shape：改成 **VM.Standard.E2.1.Micro**（AMD。别选 ARM／A1，抢不到而且额度已被砍半）
- **下载 SSH 私钥** —— 页面只给这一次，丢了就进不去了。
- 创建后记下 Public IP。

**再开端口：** Networking → Virtual Cloud Networks → 你的 VCN → Security Lists →
Default Security List → Add Ingress Rules，加两条：
Source `0.0.0.0/0`、IP Protocol `TCP`、Destination Port `80` 和 `443`。

> 主机内部还有一层 iptables 挡着（Oracle 镜像自带，只放行 SSH），`setup.sh` 会替你处理。

**排错提醒：Oracle 默认不放行 ICMP，从哪儿都 ping 不通，这不代表被墙。**
判断可达性请用 `curl -I https://你的域名`。

## 1. 服务端（Oracle 免费 VPS）

**前置：**
- DNS：把 `ntfy.yourdomain.com` 的 A 记录指向 VPS 公网 IP。
- Oracle：在 VCN Security List / NSG 放行入站 **80、443**；主机上也放行（如 `sudo iptables -I INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT`，Ubuntu 镜像还需 netfilter-persistent 保存）。
- 把 `server/Caddyfile` 和 `server/ntfy/server.yml` 里的 `ntfy.yourdomain.com` 换成你的域名。

**一条命令搞定（推荐）：** 把 `server/` 传到 VPS，然后

```bash
./setup.sh ntfy.yourdomain.com
```

它会检查 DNS、放行 80/443、写入域名、起容器、建账号、签 token，最后**验证一遍**
（HTTPS 发布是否 200、匿名访问是否 403），并直接打印你要粘进 `local.properties` 的三行。
可重复执行。

<details>
<summary>或者手动一步步来</summary>

**启动：**
```bash
cd server
docker compose up -d
```

**建用户、授权、发 token：**
```bash
# 建你的账号（交互式输入密码）
docker compose exec ntfy ntfy user add me

# 只给这个账号 “那一个随机 topic” 的读写权限（其它一律拒绝）
docker compose exec ntfy ntfy access me sms-7f3a9c2b1e0d rw

# 给手机 app 发一个 token（继承该账号权限）
docker compose exec ntfy ntfy token add me
# 输出 tk_xxxx... —— 记下来，下一步填进 Android
```

> topic 名字自己取一个长随机串（别用 `sms`）。`server.yml` 里的 `deny-all` 保证没登录就什么都读不到，token 泄露也只影响这一个 topic，用 `ntfy token remove` 随时吊销。

**⚠️ 千万别用 `docker compose down -v`** —— `-v` 会删掉数据卷，你的账号和 token 全没，
所有设备都要重新配。停服务用 `docker compose down`（不带 `-v`）或 `docker compose stop`。

> 镜像版本已固定（ntfy v2.27.0 / caddy 2.8）。这个容器管着你的账号库，不该在你不知情时
> 被自动大版本升级。要升级就手动改 tag，升级前先备份 `ntfy-data` 卷。

</details>

---

## 2. 接收端（浏览器，零安装）

浏览器打开 `https://ntfy.yourdomain.com`，用 `me` 登录，订阅你的 topic。不用装任何东西，
换设备再开一次网页即可。

已实测（浏览器通知权限为「已阻止」状态下）：

- **新短信会自己出现在页面上，不用刷新** —— 页面维持着一条长连接。
- **浏览器标签标题会变成 `(1) ntfy`** 这样的未读计数。所以把这个页面固定
  （pin）在标签栏，不用盯着也能一眼看出来了新短信。
- 侧边栏 topic 上也有未读数字角标。

**唯一要注意的**：服务器只保留 24 小时的消息（`server.yml` 的 `cache-duration`）。
你是靠翻页面看历史的，所以这个值就是你的历史长度 —— 想留更久就调大它。
（没开浏览器的那段时间收到的短信，下次打开页面会补出来，只要没超过这个时限。）

> 若哪天把服务器放到 Cloudflare 代理（橙云）后面，订阅要用 `/ws`（WebSocket）而不是默认的
> `/json` 流 —— Cloudflare 会缓冲流式响应，导致 524。

---

## 3. Android 端（发送方）

1. 用 Android Studio 打开 `android/`（Gradle Wrapper 已生成好）。
2. 把 `local.properties.example` 里的三个 `NTFY_` 配置复制到 `android/local.properties`，
   填上你的域名 / topic / token。
   **注意：注释必须单独一行** —— `java.util.Properties` 没有行内注释，
   写成 `NTFY_TOKEN=tk_xxx  # 说明` 会把 ` # 说明` 当成 token 的一部分，导致 401。
3. 连上那台插 SIM 的手机，Run。首次打开授予短信权限。
4. **务必**在系统设置里把本应用**关闭电池优化 / 加入白名单**（国产 ROM 尤其重要，否则后台会被杀、消息延迟）。

### ⚠️ 最重要的一条：不要「强行停止」本应用

Android 规定：应用一旦被**强行停止**（设置里的「强行停止」、安全软件的「一键清理」、
部分国产 ROM 的后台清理），就进入 stopped 状态，**系统不再向它投递任何广播** ——
包括短信广播。此后收到的短信会**直接丢失，没有任何提示**，直到你手动打开一次 app。

这不是本应用的 bug，是系统机制，应用自身无法检测也无法自救。已在模拟器上实测确认。

所以请务必：
- 把本应用加入清理软件/电池优化的**白名单**；
- 在「最近任务」里**锁定**本应用（国产 ROM 多有此功能，防止上划清理）；
- **重装或更新 app 后，一定要手动打开一次**（新安装的应用同样处于 stopped 状态）。

判断是否正常：打开 app 看到两个 ✅ 即代表已恢复接收。

自测转发逻辑（状态码 → 重试策略、标题编码）：
```bash
cd android && ./gradlew test
```

> 已在本机实测：Gradle wrapper 已生成，`./gradlew test` 与 `./gradlew assembleDebug` 均通过；
> 服务端配置也已用真实 ntfy 2.27 容器验证过（见下）。

### 已在 Android 模拟器（API 36）上实测通过的场景

| 场景 | 结果 |
|---|---|
| 中文短信、发件人标题 | 原样送达 |
| 超长多段短信（560 字 / 约 9 段） | 拼接完整 |
| 断网期间收到短信 | 排队不丢，恢复网络约 8 秒补发 |
| **设备重启**（队列中有未发送的短信） | 跨重启保留，开机后自动补发，**全程无需打开 app** |
| 服务器宕机后恢复 | 约 10 秒内自动补发 |
| 服务器拒绝（HTTP 403） | 弹通知告警，不静默丢弃 |
| **应用被强行停止** | **短信丢失**（系统机制，见下方警告） |

---

## 安全边界（当前）

- 传输：Caddy 自动 Let's Encrypt，全程 HTTPS。**app 强制要求 `NTFY_URL` 以 `https://` 开头**，
  否则直接拒绝发送 —— 验证码不可能走明文。
- 鉴权：`deny-all` + 每设备 token；topic 名随机是额外一层。
- token 不进源码：走 `local.properties` → `BuildConfig`，已 gitignore。
- 配置缺失时 app 首页会显示 ❌ 并直接失败，不会“看起来在跑但一条都收不到”。
- 转发若永久失败（token 错、服务器拒绝），转发手机上会弹一条通知告诉你坏了，
  绝不静默丢弃。通知只说“失败了”，不含短信内容。
- 服务器只开 `enable-login`，`enable-signup` 关闭 —— 只有你手动建的账号存在，外人无法注册。
- **信任假设：你信任自己这台 VPS**（ntfy 服务端能看到短信明文）。
  若哪天连 VPS 都不想信，再加客户端加密（手机端 libsodium sealed box 加密正文、私钥只在接收设备、VPS 只存密文）——代价是不能再用 ntfy 现成客户端。现在不需要。
