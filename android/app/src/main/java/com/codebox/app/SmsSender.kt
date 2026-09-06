package com.codebox.app

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// Outbound side. The web enqueues an encrypted {to, body, sim}; the phone (default SMS app)
// polls this queue, decrypts with the same SMS_KEY, sends, and acks. The server only holds
// ciphertext, mirroring the inbound E2E model.

// Reverse of SyncWorker.encrypt: v1: + base64(iv‖ct) -> JSON. Returns null on any tamper.
fun openSealed(keyHex: String, payload: String): JSONObject? {
    if (!payload.startsWith("v1:")) return null
    return try {
        val raw = Base64.getDecoder().decode(payload.substring(3))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(hexToBytes(keyHex), "AES"),
            GCMParameterSpec(128, raw.copyOfRange(0, 12)),
        )
        JSONObject(String(cipher.doFinal(raw.copyOfRange(12, raw.size)), Charsets.UTF_8))
    } catch (e: Exception) {
        Log.w(TAG, "decrypt outbox failed", e)
        null
    }
}

// A gate that stops a send before it starts, carrying the code that says which gate it was.
// Thrown rather than returned so every early exit funnels through the one catch in sendSms —
// nothing may leave that function by any other door (see the comment there).
private class SendFail(val code: String, val why: String) : Exception(why)

// SmsManager for a chosen SIM slot (0/1). Only slot == null ("默认") uses the system default
// subscription. Asking for SIM 1 and quietly sending on SIM 2 used to be the behaviour here; it is
// both wrong (the message leaves on the wrong card, with the wrong number and the wrong balance)
// and a diagnostic dead end, because the failure then looks identical to a healthy send. An
// unresolvable slot is now an error that names the slots that DO exist.
private fun smsManagerFor(ctx: Context, slot: Int?): SmsManager {
    @Suppress("DEPRECATION")
    val base: SmsManager = (if (Build.VERSION.SDK_INT >= 31) ctx.getSystemService(SmsManager::class.java)
                            else SmsManager.getDefault())
        ?: throw SendFail(Send.UNKNOWN, "系统未提供 SmsManager")
    if (slot == null) return base
    val subs = activeSubs(ctx)
        ?: throw SendFail(Send.SUBSCRIPTION_UNAVAILABLE, "指定 SIM ${slot + 1}，但读不到卡列表（READ_PHONE_STATE 未授予）")
    val sub = subs.firstOrNull { it.slot == slot }
        ?: throw SendFail(
            Send.SUBSCRIPTION_UNAVAILABLE,
            "指定 SIM ${slot + 1} 无对应卡；在用：" +
                (subs.joinToString("/") { "SIM ${it.slot + 1}" }.ifEmpty { "无" }),
        )
    // createForSubscriptionId is API 31. compileSdk 34 compiles the call happily, but on an
    // Android 8-11 handset the method is simply not there and the platform throws
    // NoSuchMethodError — an Error, not an Exception, so the previous `catch (e: Exception)` did
    // not catch it and it unwound straight out of the send. minSdk here is 26, and both OPPOs are
    // below 31. getSmsManagerForSubscriptionId is the API 22 equivalent (deprecated at 31).
    return try {
        if (Build.VERSION.SDK_INT >= 31) base.createForSubscriptionId(sub.subId)
        else @Suppress("DEPRECATION") SmsManager.getSmsManagerForSubscriptionId(sub.subId)
    } catch (e: Throwable) {
        throw SendFail(
            Send.SUBSCRIPTION_UNAVAILABLE,
            "SIM ${slot + 1}(sub=${sub.subId}) 绑定失败：${e.javaClass.simpleName}",
        )
    }
}

// Subscription behind a slot (0/1), or null when unknown. Only used to tag the stored copy of a
// sent message with its SIM — the send path itself resolves the slot through smsManagerFor, which
// refuses rather than falls back.
private fun subIdForSlot(ctx: Context, slot: Int?): Int? {
    if (slot == null) return null
    return activeSubs(ctx)?.firstOrNull { it.slot == slot }?.subId
}

// Sends and blocks until every part reports a delivery result (or times out). Safe only off the
// main thread — the poll loop calls it from a background executor.
//
// NOTHING may escape this function. Every gate, every platform exception and every timeout comes
// back as a SendOutcome, because the caller's contract is that a claimed outbox row is ALWAYS
// acked. The previous version resolved the SmsManager, split the message and registered the
// receiver *outside* its try block, so a throw from any of the three unwound straight past the
// ack — the row stayed "发送中" server-side with no reason recorded anywhere, which is exactly
// the failure that could not be diagnosed from the web.
fun sendSms(ctx: Context, to: String, body: String, slot: Int?): SendOutcome {
    val attempt = newAttemptId()
    if (to.isBlank() || body.isEmpty()) return SendOutcome(Send.EMPTY, "空号码或内容", attempt)

    // Pre-flight. These three can each make a send impossible while the other two look fine, and
    // two of them fail *silently* at the platform level — an IGNORED AppOp accepts the send and
    // drops it, returning no exception and no delivery report, i.e. it would present as a timeout.
    val caps = smsCapabilities(ctx)
    preflight(caps, attempt)?.let { return it }

    // Never the body, never the number: this line goes to logcat, which is not a private place.
    Log.i(TAG, "$attempt start slot=${slot ?: "default"} len=${body.length} ${capsCompact(caps)}")

    var receiver: BroadcastReceiver? = null
    return try {
        val sm = smsManagerFor(ctx, slot)
        val parts = sm.divideMessage(body)
            ?: throw SendFail(Send.ILLEGAL_ARGUMENT, "divideMessage 返回 null")
        if (parts.isEmpty()) throw SendFail(Send.ILLEGAL_ARGUMENT, "divideMessage 返回空列表")

        val latch = CountDownLatch(parts.size)
        // (resultCode, errorCode). The errorCode extra is the radio-technology specific value the
        // platform attaches to a failed sentIntent; reading only resultCode threw away the one
        // field that distinguishes one GENERIC_FAILURE from another.
        val results = java.util.Collections.synchronizedList(mutableListOf<Pair<Int, Int>>())
        val action = "com.codebox.app.SENT.$attempt"
        receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                results.add(resultCode to (i?.getIntExtra("errorCode", -1) ?: -1))
                latch.countDown()
            }
        }
        // Our own broadcast (the system delivers the sentIntent back to our package), so it must
        // be NOT_EXPORTED on 33+ — an exported receiver here would be a hole, and on 34 an
        // unflagged registration is a hard crash.
        if (Build.VERSION.SDK_INT >= 33)
            ctx.registerReceiver(receiver, IntentFilter(action), Context.RECEIVER_NOT_EXPORTED)
        else
            ctx.registerReceiver(receiver, IntentFilter(action))

        val sentIntents = ArrayList<PendingIntent>(parts.size)
        for (i in parts.indices) {
            sentIntents.add(
                PendingIntent.getBroadcast(
                    ctx, i, Intent(action).setPackage(ctx.packageName),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_ONE_SHOT,
                )
            )
        }
        sm.sendMultipartTextMessage(to, null, ArrayList(parts), sentIntents, null)

        if (!latch.await(SEND_WAIT_SEC, TimeUnit.SECONDS)) {
            // Genuinely unknown: the modem may well have submitted it. Treated as "do not retry"
            // upstream so a weak-signal send can't turn into two received messages.
            // 0 of N is a different diagnosis from 2 of 3: nothing came back at all means the
            // sentIntent callback itself never arrived — the broadcast was dropped, or this
            // process was frozen between the send and the report — whereas a partial count means
            // the modem is answering and simply hasn't finished.
            val got = results.size
            return SendOutcome(
                Send.TIMEOUT,
                if (got == 0) "${SEND_WAIT_SEC}s 内 0/${parts.size} 个回执（sentIntent 回调未到达：广播被丢弃或进程被冻结）"
                else "${SEND_WAIT_SEC}s 内只收到 $got/${parts.size} 个回执", attempt,
            )
        }
        val bad = results.firstOrNull { it.first != Activity.RESULT_OK }
        if (bad != null) {
            val (rc, ec) = bad
            return SendOutcome(
                sendCodeFor(rc),
                "${resultCodeName(rc)}(${rc})" + if (ec >= 0) " errorCode=$ec" else "",
                attempt,
            )
        }
        // Being the default SMS app also means owning the record of what was sent (no-op unless
        // the 抄送 switch is on).
        runCatching { storeSent(ctx, to, body, subIdForSlot(ctx, slot) ?: -1) }
        SendOutcome(Send.OK, "${parts.size}段全部回执成功", attempt)
    } catch (e: SendFail) {
        SendOutcome(e.code, e.why, attempt)
    } catch (e: SecurityException) {
        SendOutcome(Send.SECURITY_EXCEPTION, "SecurityException: ${e.message ?: "无详情"}", attempt)
    } catch (e: IllegalArgumentException) {
        SendOutcome(Send.ILLEGAL_ARGUMENT, "IllegalArgumentException: ${e.message ?: "无详情"}", attempt)
    } catch (e: Throwable) {
        // Throwable, not Exception, and on purpose: the contract above is absolute. Whatever this
        // was, the row still gets acked with the real class name instead of vanishing.
        SendOutcome(Send.UNKNOWN, "${e.javaClass.simpleName}: ${e.message ?: "无详情"}", attempt)
    } finally {
        receiver?.let { r -> runCatching { ctx.unregisterReceiver(r) } }
    }
}

// Long enough for a real delivery report on a weak network, short enough that two queued messages
// still finish inside the service's wake lock and the server's 5-minute claim window.
private const val SEND_WAIT_SEC = 45L

// Remember the last send outcome on the device, so it rides up in the devinfo blob and shows on the
// web card even when the outbox row only got the server's generic "多次尝试未送达" (which fires when
// the phone never acked). This is the real, per-attempt reason.
private fun recordLastSend(ctx: Context, outboxId: Long?, out: SendOutcome) {
    val who = if (outboxId != null) "#$outboxId " else "本机测试 "
    ctx.applicationContext.getSharedPreferences("dev", Context.MODE_PRIVATE)
        .edit().putString("lastSend", who + out.line()).apply()
}

// Public wrapper for the on-device test dialog: same send path as the web, minus the network.
fun sendSmsLocally(ctx: Context, to: String, body: String, slot: Int?): SendOutcome =
    sendSms(ctx, to, body, slot).also { recordLastSend(ctx, null, it) }

// --- outbox ------------------------------------------------------------------------------------

// Pull pending sends, send each, ack. Called on a background thread by ForwardService's poller.
fun pollOutbox(ctx: Context) {
    if (!configured()) return
    // Poll bases in priority order; the first that answers /api/outbox (which also stamps the
    // heartbeat) is used for the whole cycle — acks go to the same door. A blocked or dead primary
    // falls through to the next; if none answer, the reason is recorded rather than swallowed.
    val dev = deviceId(ctx)
    var lastErr = "NO_BASE"
    for (base in bases()) {
        val res = httpGetDiag("$base/api/outbox?dev=$dev")
        val bodyText = res.body
        if (bodyText == null) { lastErr = res.error; continue }
        notePoll(ctx, res.error)
        runCatching { reportDevInfo(ctx, base, dev) }
        val arr = try { JSONArray(bodyText) } catch (e: Exception) {
            notePoll(ctx, "OUTBOX_JSON_INVALID"); return
        }
        for (i in 0 until arr.length()) {
            // Nothing here may abort the cycle. One row that throws used to take the remaining
            // rows, the ack and pollDeletions down with it.
            runCatching { handleOutboxRow(ctx, base, arr.getJSONObject(i)) }
                .onFailure { Log.e(TAG, "outbox row handling failed", it) }
        }
        runCatching { pollDeletions(ctx, base) }
        return
    }
    notePoll(ctx, lastErr)
}

// One claimed row: decrypt, send, ack. Always acks — including for a row it refuses to re-send.
private fun handleOutboxRow(ctx: Context, base: String, row: org.json.JSONObject) {
    val id = row.getLong("id")
    // Already handled, ack lost. The server hands a claimed row back after its claim window, so
    // without this a dropped ack means the recipient receives the SMS a second time. "Handled"
    // deliberately includes a timeout, whose SMS may well have gone out — an unacknowledged send
    // is unknown, not absent, and duplicating it is the worse of the two mistakes.
    doneOutcome(ctx, id)?.let { prior ->
        Log.w(TAG, "outbox #$id re-served; re-acking ${prior.code} instead of re-sending")
        ackOutbox(base, id, prior); return
    }
    noteOutboxSeen(ctx, id)
    val cmd = openSealed(BuildConfig.SMS_KEY, row.optString("payload"))
    val out = if (cmd == null) SendOutcome(Send.DECRYPT_FAILED, "密文无法解密（SMS_KEY 不匹配？）", newAttemptId())
    else sendSms(ctx, cmd.optString("to"), cmd.optString("body"), slotOf(cmd.optString("sim")))
    Log.i(TAG, "outbox #$id -> ${out.code} ${out.detail} [${out.attemptId}]")
    if (out.ok || out.code == Send.TIMEOUT) markDone(ctx, id, out.code)
    recordLastSend(ctx, id, out)
    ackOutbox(base, id, out)
}

// --- "already handled" ring --------------------------------------------------------------------
// The smallest thing that stops a lost ack from becoming a duplicate SMS. Not a full state
// machine: the server already owns QUEUED/CLAIMED/SENT, and all the phone has to add is "I have
// finished with this id", which one bounded string covers.
private const val DONE_RING_MAX = 40

// "12=SEND_OK,13=SEND_TIMEOUT" — newest last, oldest dropped past the cap.
internal fun doneRingPut(ring: String, id: Long, code: String, max: Int = DONE_RING_MAX): String =
    (ring.split(",").filter { it.isNotBlank() && it.substringBefore('=') != id.toString() } + "$id=$code")
        .takeLast(max).joinToString(",")

internal fun doneRingGet(ring: String, id: Long): String? =
    ring.split(",").firstOrNull { it.substringBefore('=') == id.toString() }
        ?.substringAfter('=')?.takeIf { it.isNotBlank() }

private fun doneOutcome(ctx: Context, id: Long): SendOutcome? {
    val ring = ctx.getSharedPreferences("outbox", Context.MODE_PRIVATE).getString("done", "").orEmpty()
    val code = doneRingGet(ring, id) ?: return null
    return SendOutcome(code, "此前已处理，重发请求已忽略", "replay")
}

private fun markDone(ctx: Context, id: Long, code: String) {
    val p = ctx.getSharedPreferences("outbox", Context.MODE_PRIVATE)
    p.edit().putString("done", doneRingPut(p.getString("done", "").orEmpty(), id, code)).apply()
}

// --- poll observability --------------------------------------------------------------------
// "did the web command even reach this phone" is a different question from "did the SMS go out",
// and until these were recorded the two were indistinguishable from the browser.
private fun notePoll(ctx: Context, err: String) {
    ctx.getSharedPreferences("outbox", Context.MODE_PRIVATE).edit()
        .putLong("lastPollAt", System.currentTimeMillis())
        .putString("lastPollErr", err)
        .apply()
}

private fun noteOutboxSeen(ctx: Context, id: Long) {
    ctx.getSharedPreferences("outbox", Context.MODE_PRIVATE).edit()
        .putLong("lastOutboxAt", System.currentTimeMillis())
        .putLong("lastOutboxId", id)
        .apply()
}

// (millis since the last completed poll or -1, why it failed or "", last outbox id or -1)
fun pollStatus(ctx: Context): Triple<Long, String, Long> {
    val p = ctx.getSharedPreferences("outbox", Context.MODE_PRIVATE)
    val at = p.getLong("lastPollAt", 0L)
    return Triple(
        if (at == 0L) -1L else System.currentTimeMillis() - at,
        p.getString("lastPollErr", "").orEmpty(),
        p.getLong("lastOutboxId", -1L),
    )
}

// Mirror web deletions onto this phone. A message can live in three places here: our own list
// (CodeStore), the system SMS database (only if we were the default SMS app when it arrived — and
// only a default app may delete from it), and the web. A web delete queues an encrypted row; we
// decrypt it and remove the local copies.
//
// Two cursors. `hw` advances once our own list is cleaned — always possible. `hwSys` advances only
// when we could also clean the system SMS, i.e. we are default: a phone that is NOT default right
// now keeps those rows pending and finishes them when it becomes default again. A single cursor
// skipped them for good — the "手机上没删" the user saw on a phone whose default keeps dropping.
// A phone that was never default has no system copies, so it advances both (no pointless retry).
private fun pollDeletions(ctx: Context, base: String) {
    val p = ctx.getSharedPreferences("del", Context.MODE_PRIVATE)
    val hw = p.getLong("hw", 0L)
    val hwSys = p.getLong("hwSys", 0L)
    val since = minOf(hw, hwSys)
    val json = httpGet("$base/api/deletions?since=$since") ?: return
    val arr = try { JSONArray(json) } catch (e: Exception) { return }
    val isDefault = isDefaultSmsApp(ctx)   // RoleManager-backed; the legacy check lags the role
    val everDefault = p.getBoolean("everDefault", false) || isDefault
    var maxId = since
    var removedAny = false
    for (i in 0 until arr.length()) {
        val row = arr.getJSONObject(i)
        val id = row.getLong("id")
        val o = openSealed(BuildConfig.SMS_KEY, row.getString("payload"))
        val sender = o?.optString("s").orEmpty()
        val body = o?.optString("b").orEmpty()
        if (sender.isNotEmpty() && body.isNotEmpty()) {
            if (id > hw) runCatching { if (CodeStore.remove(ctx, sender, body) > 0) removedAny = true }
            if (isDefault && id > hwSys) runCatching { deleteSystemSms(ctx, sender, body) }
        }
        if (id > maxId) maxId = id
    }
    val e = p.edit()
    if (maxId > hw) e.putLong("hw", maxId)
    if ((isDefault || !everDefault) && maxId > hwSys) e.putLong("hwSys", maxId)
    if (isDefault) e.putBoolean("everDefault", true)
    e.apply()
    // An open list should drop the row now, not on the next launch.
    if (removedAny) runCatching { ctx.sendBroadcast(Intent(NEW_ACTION).setPackage(ctx.packageName)) }
}

// Delete the system-SMS copy. The stored row may have been written by the stock app (while it was
// default), which can store the address differently (+86, spacing) — so match the number by its
// digits, not verbatim; and the forwarded body may have been clamped, so accept a stored body that
// starts with it. Candidates are found by body, then filtered by address in code.
private fun deleteSystemSms(ctx: Context, sender: String, body: String) {
    val cr = ctx.contentResolver
    val uri = android.provider.Telephony.Sms.CONTENT_URI
    val ids = ArrayList<Long>()
    cr.query(
        uri, arrayOf("_id", "address"), "body=? OR body LIKE ? ESCAPE '\\'",
        arrayOf(body, likeEscape(body) + "%"), null,
    )?.use { c ->
        while (c.moveToNext()) if (sameAddress(c.getString(1), sender)) ids.add(c.getLong(0))
    }
    for (id in ids) runCatching { cr.delete(uri, "_id=?", arrayOf(id.toString())) }
}

// Same phone number regardless of formatting: compare the digits, dropping a leading country code
// so "+86 138 0013 8000" and "13800138000" agree. Non-numeric senders (brand names) compare verbatim.
internal fun sameAddress(a: String?, b: String?): Boolean {
    val x = a.orEmpty().trim()
    val y = b.orEmpty().trim()
    if (x == y) return true
    fun norm(s: String): String {
        var d = s.filter { it.isDigit() }
        if (d.length == 13 && d.startsWith("86")) d = d.substring(2)
        return d
    }
    val nx = norm(x)
    return nx.isNotEmpty() && nx == norm(y)
}

// Make a string safe as a LIKE prefix (used with ESCAPE '\').
internal fun likeEscape(s: String): String =
    s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

private fun slotOf(sim: String): Int? = sim.toIntOrNull()?.takeIf { it >= 0 }

// The SIM's own carrier, not the network it happens to be camped on. SubscriptionInfo.carrierName
// follows the serving network while roaming — a 中国电信 SIM abroad reported itself as "Sure" —
// so read the SPN burned into the SIM first and keep carrierName only as the fallback.
private fun carrierNameFor(ctx: Context, subId: Int): String {
    val spn = try {
        ctx.getSystemService(android.telephony.TelephonyManager::class.java)
            ?.createForSubscriptionId(subId)?.simOperatorName?.trim().orEmpty()
    } catch (e: Exception) { "" }
    return spn
}

// "SIM 1 · 运营商" for the subscription that received an SMS. Needs READ_PHONE_STATE; returns
// null (→ message just isn't tagged) if not granted, sub unknown, or single-SIM with no info.
fun simLabelForSub(ctx: Context, subId: Int): String? {
    if (subId < 0) return null
    return try {
        val info = ctx.getSystemService(SubscriptionManager::class.java)
            ?.getActiveSubscriptionInfo(subId) ?: return null
        val carrier = carrierNameFor(ctx, subId)
            .ifEmpty { info.carrierName?.toString()?.trim().orEmpty() }
        buildString {
            append("SIM ").append(info.simSlotIndex + 1)
            if (carrier.isNotEmpty()) append(" · ").append(carrier)
        }
    } catch (e: SecurityException) {
        null
    } catch (e: Exception) {
        null
    }
}

// A missed-call notification carries no subscription id — measured, not assumed: a real missed
// call on Android 11 posts extras of exactly {title, text, largeIcon, appInfo, showWhen}, with no
// PhoneAccountHandle and no sub id anywhere. So on a dual-SIM phone there is no honest way to say
// which card rang from the notification alone, and a wrong SIM label is worse than none. With
// exactly one active SIM there is only one possible answer, which covers most phones.
//
// Two ways out if this ever needs to work on a dual-SIM phone, neither implemented:
//   1. The notification's TAG carries the call-log row URI ("MissedCall_content://call_log/calls/N")
//      — query CallLog.Calls.PHONE_ACCOUNT_ID on it. Precise; needs READ_CALL_LOG declared.
//   2. Register a per-subscription PhoneStateListener (TelephonyManager.createForSubscriptionId is
//      API 24, unlike SmsManager's API 31 one) and remember which sub last went RINGING. Needs only
//      READ_PHONE_STATE, but it is time correlation rather than true attribution.
fun soleSimLabel(ctx: Context): String? {
    return try {
        val subs = ctx.getSystemService(SubscriptionManager::class.java)?.activeSubscriptionInfoList
        if (subs == null || subs.size != 1) return null
        simLabelForSub(ctx, subs[0].subscriptionId)
    } catch (e: SecurityException) {
        null
    } catch (e: Exception) {
        null
    }
}

// Encrypted SIM list for the web dropdown. Posting every poll would be ~4000 KV writes a day, so
// normally it only goes up when it changes — but "changed" is judged against this phone's own
// last upload, and the stored value is shared: another device (a test phone, an emulator) can
// overwrite it and this one would never notice. Re-posting every 30 minutes heals that on its own
// while still costing under 50 writes a day.
private var lastSims: String? = null
private var lastSimsAt = 0L
private const val SIMS_REFRESH_MS = 30 * 60 * 1000L

// Reports {name, sims} for THIS device, encrypted. Keyed per device server-side, so a second
// phone no longer overwrites the first one's entry — which used to leave the web showing a SIM
// that belonged to some other handset entirely.
private fun reportDevInfo(ctx: Context, base: String, dev: String) {
    val sims = simListJson(ctx) ?: "[]"
    val caps = deviceCaps(ctx).entries.joinToString(",") { """"${it.key}":${it.value}""" }
    val (gapCount, gapMax) = aliveGaps(ctx)
    val (netWakes, netNoNet) = netWakes(ctx)
    val lastSend = ctx.getSharedPreferences("dev", Context.MODE_PRIVATE).getString("lastSend", "").orEmpty()
    // The send gates, verbatim, so the browser sees exactly what the phone sees. Without this a
    // failed send could not be attributed from the web: role, permission and AppOps come apart
    // independently, and the card previously showed only a single "可发送" boolean for all three.
    val smsCap = capsCompact(smsCapabilities(ctx))
    // Deliberately NOT the poll timestamp: the server stamps that itself on every /api/outbox,
    // and putting a value that changes each cycle in here would defeat the write-dedup below and
    // turn ~50 D1 writes a day into ~4300. Only the two stable facts travel — why the last poll
    // failed, and the last outbox row this phone saw.
    val (_, pollErr, lastOut) = pollStatus(ctx)
    val json = """{"n":"${jsonEscape(deviceName())}","s":$sims,"c":{$caps},"g":[$gapCount,$gapMax,${worstGapMinutes(ctx)},$netWakes,$netNoNet],"t":"${currentTransport(ctx)}","os":"${jsonEscape(osLabel())}","ls":"${jsonEscape(lastSend)}","v":"${jsonEscape(BuildConfig.VERSION_NAME)}","cap":"${jsonEscape(smsCap)}","pp":["${jsonEscape(pollErr)}",$lastOut]}"""
    val now = System.currentTimeMillis()
    if (json == lastSims && now - lastSimsAt < SIMS_REFRESH_MS) return
    if (httpPostText("$base/api/devinfo?dev=$dev", encrypt(BuildConfig.SMS_KEY, json))) {
        lastSims = json; lastSimsAt = now
    }
}

// [{slot, name}] for each active SIM. name = "SIM 1 · 运营商 · 末4位" (number is usually blank
// on modern Android). Needs READ_PHONE_STATE; returns null (→ web keeps fixed SIM1/SIM2) if not.
private fun simListJson(ctx: Context): String? {
    return try {
        val subs = ctx.getSystemService(SubscriptionManager::class.java)
            ?.activeSubscriptionInfoList ?: return null
        if (subs.isEmpty()) return null
        val arr = JSONArray()
        for (info in subs) {
            val carrier = carrierNameFor(ctx, info.subscriptionId)
                .ifEmpty { info.carrierName?.toString()?.trim().orEmpty() }
            val num = info.number?.trim().orEmpty()
            val name = buildString {
                append("SIM ").append(info.simSlotIndex + 1)
                if (carrier.isNotEmpty()) append(" · ").append(carrier)
                if (num.length >= 4) append(" · ").append(num.takeLast(4))
            }
            arr.put(JSONObject().put("slot", info.simSlotIndex).put("name", name))
        }
        arr.toString()
    } catch (e: SecurityException) {
        null   // READ_PHONE_STATE not granted
    } catch (e: Exception) {
        null
    }
}

// A GET that says WHY it failed. The old one collapsed DNS failure, a TLS error, a 403 from a
// wrong token and a 500 into the same `null`, so a phone that could not reach the server at all
// was indistinguishable from one with nothing to send — and "网页发的命令没到手机" could not be
// separated from "手机收到了但发不出去". error is "" only on success.
internal class HttpResult(val body: String?, val error: String)

internal fun classify(e: Exception, connected: Boolean): String = when (e) {
    is java.net.UnknownHostException -> "DNS"
    is javax.net.ssl.SSLException -> "TLS"
    is java.net.SocketTimeoutException -> if (connected) "READ_TIMEOUT" else "CONNECT_TIMEOUT"
    is java.net.ConnectException -> "CONNECT"
    else -> e.javaClass.simpleName
}

private fun httpGetDiag(url: String): HttpResult {
    var conn: HttpURLConnection? = null
    var connected = false
    return try {
        conn = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000; readTimeout = 15_000
            setRequestProperty("Authorization", "Bearer ${BuildConfig.NTFY_TOKEN}")
        }
        conn.connect()
        connected = true
        val code = conn.responseCode
        if (code != 200) HttpResult(null, "HTTP_$code")
        else HttpResult(conn.inputStream.bufferedReader().use { it.readText() }, "")
    } catch (e: Exception) {
        HttpResult(null, classify(e, connected))
    } finally {
        conn?.disconnect()
    }
}

private fun httpGet(url: String): String? = httpGetDiag(url).body

private fun httpPostText(url: String, body: String): Boolean {
    var conn: HttpURLConnection? = null
    return try {
        conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"; doOutput = true
            connectTimeout = 15_000; readTimeout = 15_000
            setRequestProperty("Authorization", "Bearer ${BuildConfig.NTFY_TOKEN}")
            setRequestProperty("Content-Type", "text/plain; charset=utf-8")
        }
        conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        conn.responseCode in 200..299
    } catch (e: Exception) {
        false
    } finally {
        conn?.disconnect()
    }
}

// Report a send's result. Tries every base, not just the one the row came from: an ack that does
// not land is what turns a delivered SMS into a duplicate five minutes later, so it is worth one
// more round trip over the backup domain before giving up. The phone's own done-ring is the
// backstop for the case where all of them fail.
private fun ackOutbox(base: String, id: Long, out: SendOutcome) {
    val detail = if (out.ok) out.attemptId else "${out.code}｜${out.detail} [${out.attemptId}]"
    val body = """{"id":$id,"ok":${out.ok},"detail":"${jsonEscape(detail)}"}"""
    val targets = listOf(base) + bases().filter { it != base }
    for (b in targets) {
        var conn: HttpURLConnection? = null
        try {
            conn = (URL("$b/api/outbox/ack").openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"; doOutput = true
                connectTimeout = 15_000; readTimeout = 15_000
                setRequestProperty("Authorization", "Bearer ${BuildConfig.NTFY_TOKEN}")
                setRequestProperty("Content-Type", "application/json")
            }
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            if (conn.responseCode in 200..299) return
        } catch (e: Exception) {
            Log.w(TAG, "ack failed id=$id via $b", e)
        } finally {
            conn?.disconnect()
        }
    }
    Log.e(TAG, "ack #$id could not be delivered to any base; done-ring prevents a resend")
}
