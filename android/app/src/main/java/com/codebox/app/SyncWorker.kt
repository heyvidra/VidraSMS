package com.codebox.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

const val TAG = "CodeBox"
const val NEW_ACTION = "com.codebox.app.NEW"

// Single funnel for both capture paths: the SMS broadcast (IncomingReceiver, only fires when
// the restricted SMS permission is actually held) and the notification listener (CodeListener,
// works on a sideloaded install). CodeStore.add dedups, so an SMS seen by both is stored and
// forwarded exactly once. Must be called off the main thread — it touches SQLite and WorkManager.
// Returns false when the message was a duplicate inside the dedup window, so a caller that also
// wants to write it into the system SMS database can skip that too rather than storing it twice.
// The cheap half: dedup and record locally. Split out from the upload so a caller can get the
// phone-local work done — storing the SMS where the stock Messages app reads it, and posting the
// notification — before anything touches the network. Returns false for a duplicate.
fun recordIncoming(context: Context, sender: String, body: String, ts: Long): Boolean {
    val app = context.applicationContext
    if (!CodeStore.add(app, sender, clampBody(body, MAX_PLAIN_BYTES), ts)) return false
    // Nudge an open MainActivity to refresh; setPackage keeps it internal to this app.
    app.sendBroadcast(Intent(NEW_ACTION).setPackage(app.packageName))
    return true
}

fun forwardNow(context: Context, sender: String, body: String, ts: Long, simLabel: String? = null): Boolean {
    if (!recordIncoming(context, sender, body, ts)) return false
    deliver(context, sender, body, ts, simLabel)
    return true
}

// The expensive half: get it to the server, or queue it durably for retry.
fun deliver(context: Context, sender: String, body: String, ts: Long, simLabel: String? = null) {
    val app = context.applicationContext
    val clamped = clampBody(body, MAX_PLAIN_BYTES)

    // Deliver it right here, while the SMS broadcast still has the device awake, holding a wake
    // lock so a re-suspend can't cut the request in half. This is the important part: WorkManager
    // runs on JobScheduler, and Doze defers jobs to a maintenance window — which is why a locked
    // phone received messages and forwarded none of them. The queue below stays as the retry path
    // for when this attempt fails (offline, server down, or a genuinely permanent rejection that
    // SyncWorker will surface as a notification).
    if (configured()) {
        val wl = app.getSystemService(android.os.PowerManager::class.java)
            ?.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "codebox:forward")
        runCatching { wl?.acquire(60_000L) }
        val outcome = try {
            runCatching { uploadMessage(app, sender, clamped, ts, simLabel, QUICK_MS) }
                .getOrDefault(Outcome.RETRY)
        } finally {
            runCatching { if (wl?.isHeld == true) wl.release() }
        }
        if (outcome == Outcome.SUCCESS) return   // delivered; no need for the retry queue
        Log.w(TAG, "direct forward failed ($outcome), queueing")
    }

    val request = OneTimeWorkRequestBuilder<SyncWorker>()
        .setInputData(
            Data.Builder().putString("sender", sender).putString("body", clamped).putLong("ts", ts)
                .putString("sim", simLabel).build()
        )
        .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
        // LINEAR, not EXPONENTIAL: offline, the CONNECTED constraint parks the worker so no
        // attempts burn and reconnecting delivers at once; attempts only pile up when the server
        // is down, where exponential backoff would still be waiting long after it returned.
        .setBackoffCriteria(BackoffPolicy.LINEAR, 15, TimeUnit.SECONDS)
        .build()
    // Wait for the enqueue to commit to disk so the row survives the process dying right after.
    try {
        WorkManager.getInstance(app).enqueue(request).result.get(20, TimeUnit.SECONDS)
    } catch (e: Exception) {
        Log.e(TAG, "enqueue failed", e)
    }
}

enum class Outcome { SUCCESS, RETRY, FAILURE }

// Pure decision so it can be unit-tested without Android. 4xx (except 429) = don't retry
// (bad token/topic won't fix itself); 5xx / 429 / network error = retry with backoff.
fun outcomeFor(code: Int): Outcome = when {
    code in 200..299 -> Outcome.SUCCESS
    code == 429 || code in 500..599 -> Outcome.RETRY
    code in 400..499 -> Outcome.FAILURE
    else -> Outcome.RETRY
}

// ntfy accepts UTF-8 titles, but HttpURLConnection encodes header values as ISO-8859-1,
// which would mangle a Chinese sender name. RFC 2047 keeps the wire bytes ASCII and ntfy
// decodes it back — verified against ntfy 2.27.
fun encodeTitle(sender: String): String {
    val s = sender.trim().ifBlank { return "SMS" }
    if (s.all { it.code in 32..126 }) return s
    val b64 = Base64.getEncoder().encodeToString(s.toByteArray(Charsets.UTF_8))
    return "=?UTF-8?B?$b64?="
}

// ntfy rejects bodies of 4096 bytes or more with a 400 (measured against 2.27), which
// outcomeFor treats as permanent — a long Chinese SMS would vanish silently. Truncating
// keeps the head, and any OTP lives in the head.
// ponytail: truncate rather than split into several messages; a >4095-byte SMS is already
// at the edge of what carriers concatenate. Split it here if that ever stops being true.
const val NTFY_MAX_BYTES = 4095

fun clampBody(body: String, limit: Int = NTFY_MAX_BYTES): String {
    val bytes = body.toByteArray(Charsets.UTF_8)
    if (bytes.size <= limit) return body
    val marker = "…[截断]"
    val room = limit - marker.toByteArray(Charsets.UTF_8).size
    // Cutting mid-character leaves U+FFFD after decoding; drop those so the text stays clean.
    return String(bytes.copyOf(room), Charsets.UTF_8).trimEnd('�') + marker
}

// ntfy stamps messages with delivery time, not SMS time. After an offline stretch a batch
// would all look like it arrived now, so note the original time when they differ.
fun formatBody(body: String, ts: Long, now: Long): String {
    if (ts <= 0L || now - ts < 120_000L) return body
    val t = SimpleDateFormat("MM-dd HH:mm", Locale.getDefault()).format(Date(ts))
    return "[原时间 $t]\n$body"
}

// --- end-to-end encryption -------------------------------------------------------
// The server only ever sees ciphertext. SMS_KEY lives in local.properties and in the
// browser's localStorage; it is never sent anywhere. Losing it makes stored messages
// permanently unreadable — that is the point, and the cost.

// Ciphertext is base64, which inflates by 4/3, and AES-GCM adds a 12-byte IV and a
// 16-byte tag. Clamp the plaintext so the encoded payload still clears NTFY_MAX_BYTES:
// ceil((3000+28)/3)*4 + len("v1:") = 4043 < 4095.
const val MAX_PLAIN_BYTES = 3000

fun hexToBytes(hex: String): ByteArray =
    ByteArray(hex.length / 2) { ((hex[it * 2].digitToInt(16) shl 4) or hex[it * 2 + 1].digitToInt(16)).toByte() }

// JSON by hand rather than pulling in a parser for two fields — but the escaping has to
// be right or a quote in an SMS produces a payload the browser cannot parse.
fun jsonEscape(s: String): String {
    val sb = StringBuilder(s.length + 16)
    for (c in s) when {
        c == '"' -> sb.append("\\\"")
        c == '\\' -> sb.append("\\\\")
        c == '\n' -> sb.append("\\n")
        c == '\r' -> sb.append("\\r")
        c == '\t' -> sb.append("\\t")
        c < ' ' -> sb.append("\\u%04x".format(c.code))
        else -> sb.append(c)
    }
    return sb.toString()
}

fun encrypt(keyHex: String, plaintext: String): String {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(hexToBytes(keyHex), "AES"), GCMParameterSpec(128, iv))
    val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
    return "v1:" + Base64.getEncoder().encodeToString(iv + ct)
}

// Packs sender, body and (optionally) the receiving SIM into one ciphertext so the server sees
// none of it. "k" (card) is omitted when unknown to keep the payload small.
fun sealMessage(keyHex: String, sender: String, body: String, card: String? = null,
                dev: String? = null): String {
    val senderJson = jsonEscape(sender)
    val cardJson = if (!card.isNullOrBlank()) jsonEscape(card) else null
    // "d" is this device's id, so the web can say WHICH phone received the message. It rides
    // inside the ciphertext rather than as a request field: the server has no business knowing
    // which handset a given message came through.
    val devJson = if (!dev.isNullOrBlank()) jsonEscape(dev) else null
    // Reserve room for the JSON scaffolding, the escaped sender, card and device id.
    val overhead = 24 + (cardJson?.let { it.toByteArray(Charsets.UTF_8).size + 8 } ?: 0) +
        (devJson?.let { it.toByteArray(Charsets.UTF_8).size + 8 } ?: 0)
    val room = (MAX_PLAIN_BYTES - senderJson.toByteArray(Charsets.UTF_8).size - overhead)
        .coerceAtLeast(64)
    // Clamp the ESCAPED body, not the raw one. Escaping expands: a quote or newline becomes two
    // bytes and a control character six, so a body clamped raw to exactly room could ship well
    // over it — past the server's limit, where it is rejected as a permanent 4xx and the message
    // is dropped rather than retried.
    var bodyJson = jsonEscape(clampBody(body, room))
    while (bodyJson.toByteArray(Charsets.UTF_8).size > room) {
        val over = bodyJson.toByteArray(Charsets.UTF_8).size - room
        val next = jsonEscape(clampBody(body, (room - over).coerceAtLeast(16)))
        if (next == bodyJson) break        // cannot shrink further; ship what we have
        bodyJson = next
    }
    val payload = buildString {
        append("{\"s\":\"").append(senderJson).append("\",\"b\":\"").append(bodyJson).append("\"")
        if (cardJson != null) append(",\"k\":\"").append(cardJson).append("\"")
        if (devJson != null) append(",\"d\":\"").append(devJson).append("\"")
        append("}")
    }
    return encrypt(keyHex, payload)
}

// NTFY_URL may hold several https bases (comma/space/newline separated) in priority order.
// Every base points at the SAME worker (same D1/KV), so they are interchangeable front doors:
// the first that answers wins, and a blocked or dead primary transparently fails over to the
// next. A single-domain setup just yields a one-element list. Pure so it can be unit-tested.
fun parseBases(raw: String): List<String> =
    raw.split(',', ' ', '\n', '\t', '\r')
        .map { it.trim().trimEnd('/') }
        .filter { it.startsWith("https://") }

fun bases(): List<String> = parseBases(BuildConfig.NTFY_URL)

// True only when local.properties actually supplied at least one https endpoint, a token, a key.
fun configured(): Boolean =
    bases().isNotEmpty() &&
        BuildConfig.NTFY_TOPIC.isNotBlank() &&
        BuildConfig.NTFY_TOKEN.isNotBlank() &&
        BuildConfig.SMS_KEY.length == 64


// One attempt at delivering a message: encrypt once, then offer the same ciphertext to each base
// in priority order. Shared by the immediate attempt in forwardNow and by SyncWorker's retry, so
// both agree on what counts as permanent. Sender travels inside the ciphertext (no Title header),
// so the server sees only that something arrived, not who texted.
fun uploadMessage(ctx: Context, sender: String, body: String, ts: Long, sim: String?,
                  timeoutMs: Int = PATIENT_MS): Outcome {
    val payload = sealMessage(
        BuildConfig.SMS_KEY, sender, formatBody(body, ts, System.currentTimeMillis()), sim,
        deviceId(ctx),
    )
    for (base in bases()) {
        // dev in the clear (same opaque id already sent to /api/outbox & /api/devinfo) so the
        // server can bump this phone's heartbeat on every forward. A ColorOS-frozen phone stops
        // polling but still forwards via the SMS broadcast — without this it reads "offline" while
        // it is in fact delivering, which is exactly the false alarm that looked like a failure.
        val code = postForward(
            "$base/${BuildConfig.NTFY_TOPIC}?dev=${deviceId(ctx)}", payload, timeoutMs)
        when {
            code < 0 -> continue                          // this base unreachable → next door
            outcomeFor(code) == Outcome.SUCCESS -> return Outcome.SUCCESS
            outcomeFor(code) == Outcome.FAILURE -> return Outcome.FAILURE
            else -> continue                              // 5xx/429 — another base may be healthy
        }
    }
    return Outcome.RETRY   // all blocked or all 5xx
}

// POSTs the payload to one endpoint. Returns the HTTP status, or -1 on a network/TLS failure
// so the caller can tell "this door is blocked, try the next" from "the server said no".
// Two budgets. The patient one is for SyncWorker, which runs in its own job and can wait. The
// quick one is for the inline attempt inside the SMS broadcast: that runs on borrowed time — a
// broadcast receiver held open past ~60s is an ANR, and 2 bases x (10s connect + 10s read) plus
// the WorkManager enqueue reached exactly that. Failing fast there costs nothing, because the
// queued retry then tries again patiently.
const val PATIENT_MS = 10_000
const val QUICK_MS = 6_000

private fun postForward(endpoint: String, payload: String, timeoutMs: Int = PATIENT_MS): Int {
    var conn: HttpURLConnection? = null
    return try {
        conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            doOutput = true
            setRequestProperty("Authorization", "Bearer ${BuildConfig.NTFY_TOKEN}")
            setRequestProperty("Content-Type", "text/plain; charset=utf-8")
        }
        conn.outputStream.use { it.write(payload.toByteArray(Charsets.US_ASCII)) }
        conn.responseCode
    } catch (e: Exception) {
        -1
    } finally {
        conn?.disconnect()
    }
}

class SyncWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        val sender = inputData.getString("sender") ?: "unknown"
        val body = inputData.getString("body") ?: ""
        val ts = inputData.getLong("ts", 0L)
        val sim = inputData.getString("sim")

        // Unconfigured build: retrying forever would silently swallow every SMS. Fail loudly
        // instead — MainActivity surfaces the same condition on screen.
        if (!configured()) {
            alertBroken("未配置转发目标")
            return Result.failure()
        }

        return when (uploadMessage(applicationContext, sender, body, ts, sim)) {
            Outcome.SUCCESS -> Result.success()
            Outcome.FAILURE -> {
                // 4xx is the same rejection (bad token/topic) on every base — permanent. Dropping
                // an OTP silently is the worst outcome, so make the breakage visible on the phone.
                Log.e(TAG, "permanent failure, dropping SMS from $sender")
                alertBroken("服务器拒绝")
                Result.failure()
            }
            Outcome.RETRY -> Result.retry()
        }
    }


    private fun alertBroken(reason: String) {
        val nm = applicationContext.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(
            NotificationChannel("broken", "同步状态", NotificationManager.IMPORTANCE_HIGH)
        )
        val n = android.app.Notification.Builder(applicationContext, "broken")
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("验证码同步失败")
            .setContentText("$reason —— 有一条未能同步")
            .setAutoCancel(true)
            .build()
        // Same id: one standing "it's broken" notice rather than one per dropped message.
        runCatching { nm.notify(1, n) }
    }
}
