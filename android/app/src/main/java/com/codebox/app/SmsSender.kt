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

// SmsManager for a chosen SIM slot (0/1). Falls back to the default SIM when the slot is
// unset, unreadable (no READ_PHONE_STATE), or empty — single-SIM phones never hit the map.
private fun smsManagerFor(ctx: Context, slot: Int?): SmsManager {
    @Suppress("DEPRECATION")
    val base = if (Build.VERSION.SDK_INT >= 31) ctx.getSystemService(SmsManager::class.java)
               else SmsManager.getDefault()
    if (slot == null) return base
    val sub = subIdForSlot(ctx, slot) ?: return base
    return try { base.createForSubscriptionId(sub) } catch (e: Exception) { base }
}

// Subscription behind a slot (0/1), or null when unknown — no READ_PHONE_STATE, empty slot,
// or a single-SIM phone. Also used to tag the stored copy of a sent message with its SIM.
private fun subIdForSlot(ctx: Context, slot: Int?): Int? {
    if (slot == null) return null
    return try {
        ctx.getSystemService(SubscriptionManager::class.java)
            ?.getActiveSubscriptionInfoForSimSlotIndex(slot)?.subscriptionId
    } catch (e: SecurityException) {
        null
    } catch (e: Exception) {
        null
    }
}

// Sends and blocks until every part reports a result (or times out). Safe only off the main
// thread — the poll loop calls it from a background executor. Returns (ok, detail-for-ack).
fun sendSms(ctx: Context, to: String, body: String, slot: Int?): Pair<Boolean, String> {
    if (to.isBlank() || body.isEmpty()) return false to "空号码或内容"
    val sm = smsManagerFor(ctx, slot)
    val parts = sm.divideMessage(body)
    val latch = CountDownLatch(parts.size)
    val codes = java.util.Collections.synchronizedList(mutableListOf<Int>())
    val action = "com.codebox.app.SENT." + System.nanoTime()

    val receiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context?, i: Intent?) { codes.add(resultCode); latch.countDown() }
    }
    // Own broadcast (system delivers the sentIntent to our package) → NOT_EXPORTED on 33+.
    if (Build.VERSION.SDK_INT >= 33)
        ctx.registerReceiver(receiver, IntentFilter(action), Context.RECEIVER_NOT_EXPORTED)
    else
        ctx.registerReceiver(receiver, IntentFilter(action))

    return try {
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

        if (!latch.await(60, TimeUnit.SECONDS)) return false to "超时"
        val bad = codes.firstOrNull { it != Activity.RESULT_OK }
        if (bad != null) return false to "结果码 $bad"
        // Being the default SMS app also means owning the record of what was sent — without this
        // the message would leave the phone without appearing in any conversation on it.
        storeSent(ctx, to, body, subIdForSlot(ctx, slot) ?: -1)
        true to ""
    } catch (e: Exception) {
        false to (e.message ?: "发送异常")
    } finally {
        runCatching { ctx.unregisterReceiver(receiver) }
    }
}

// Pull pending sends, send each, ack. Called on a background thread by CodeListener's poller.
// One at a time is fine for manual use; sendSms blocks per message.
fun pollOutbox(ctx: Context) {
    if (!configured()) return
    // Poll bases in priority order; the first that answers /api/outbox (which also stamps the
    // heartbeat) is used for the whole cycle — sims + acks go to the same door. A blocked or
    // dead primary falls through to the next; if none answer, next poll retries.
    val dev = deviceId(ctx)
    for (base in bases()) {
        val listJson = httpGet("$base/api/outbox?dev=$dev") ?: continue
        reportDevInfo(ctx, base, dev)
        val arr = try { JSONArray(listJson) } catch (e: Exception) { return }
        for (i in 0 until arr.length()) {
            val row = arr.getJSONObject(i)
            val id = row.getLong("id")
            val cmd = openSealed(BuildConfig.SMS_KEY, row.getString("payload"))
            val (ok, detail) = if (cmd == null) false to "解密失败"
                else sendSms(ctx, cmd.optString("to"), cmd.optString("body"), slotOf(cmd.optString("sim")))
            ackOutbox(base, id, ok, detail)
        }
        return
    }
}

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

// A missed-call notification carries no subscription id, so on a dual-SIM phone there is no
// honest way to say which card rang — and a wrong SIM label is worse than none. With exactly one
// active SIM there is only one possible answer, which covers most phones; otherwise stay silent.
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
    val json = """{"n":"${jsonEscape(deviceName())}","s":$sims,"c":{$caps},"g":[$gapCount,$gapMax,${worstGapMinutes(ctx)},$netWakes,$netNoNet],"t":"${currentTransport(ctx)}","v":"${jsonEscape(BuildConfig.VERSION_NAME)}"}"""
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

private fun httpGet(url: String): String? {
    var conn: HttpURLConnection? = null
    return try {
        conn = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000; readTimeout = 15_000
            setRequestProperty("Authorization", "Bearer ${BuildConfig.NTFY_TOKEN}")
        }
        if (conn.responseCode != 200) null
        else conn.inputStream.bufferedReader().use { it.readText() }
    } catch (e: Exception) {
        null
    } finally {
        conn?.disconnect()
    }
}

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

private fun ackOutbox(base: String, id: Long, ok: Boolean, detail: String) {
    var conn: HttpURLConnection? = null
    try {
        conn = (URL("$base/api/outbox/ack").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"; doOutput = true
            connectTimeout = 15_000; readTimeout = 15_000
            setRequestProperty("Authorization", "Bearer ${BuildConfig.NTFY_TOKEN}")
            setRequestProperty("Content-Type", "application/json")
        }
        val body = """{"id":$id,"ok":$ok,"detail":"${jsonEscape(detail)}"}"""
        conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        conn.responseCode   // drain; ack is best-effort
    } catch (e: Exception) {
        Log.w(TAG, "ack failed id=$id", e)
    } finally {
        conn?.disconnect()
    }
}
