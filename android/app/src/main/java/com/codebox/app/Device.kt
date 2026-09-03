package com.codebox.app

import android.content.Context
import android.os.Build
import java.security.SecureRandom

// Who this install is. Everything the phone sends upstream carries it, so the web can tell two
// phones apart instead of showing one merged, ambiguous state — which is what made "转发手机在线"
// meaningless while a test device and the real phone were both polling.
//
// The id is random and opaque: the server needs *an* identifier to key the heartbeat and the
// outbox on, but it must not learn anything from it. The readable name travels encrypted with
// the SIM list instead, the same way message bodies do.
private const val PREFS = "dev"
private const val KEY_ID = "id"

fun deviceId(ctx: Context): String {
    val p = ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    p.getString(KEY_ID, null)?.let { return it }
    // Not ANDROID_ID: that one is derived from the signing key and survives a reinstall, so two
    // installs of this app on the same phone would collide. A fresh random id is also a fresh
    // identity, which is the honest meaning of "this install".
    val bytes = ByteArray(8).also { SecureRandom().nextBytes(it) }
    val id = bytes.joinToString("") { "%02x".format(it) }
    p.edit().putString(KEY_ID, id).apply()
    return id
}

// "Xiaomi 22041216C" — shown in the web's device list. Never leaves the phone in clear text.
fun deviceName(): String {
    val maker = Build.MANUFACTURER?.trim().orEmpty().replaceFirstChar { it.uppercase() }
    val model = Build.MODEL?.trim().orEmpty()
    return when {
        model.isEmpty() -> maker.ifEmpty { "未知设备" }
        model.startsWith(maker, ignoreCase = true) || maker.isEmpty() -> model
        else -> "$maker $model"
    }
}

// OS label for the web card: "Android 11 · ColorOS V11.1" — Android from Build, ColorOS from a
// system property (best-effort, names vary across OPLUS/OPPO builds; falls back to just Android).
// Lets remote diagnosis read the ROM off the dashboard instead of asking someone to check on-device.
fun osLabel(): String {
    val android = "Android " + (Build.VERSION.RELEASE ?: Build.VERSION.SDK_INT.toString())
    // The ROM name comes FROM whichever vendor property matched — NOT hardcoded — so a Xiaomi reads
    // "MIUI", a vivo "OriginOS", a Huawei "EMUI", never a wrong "ColorOS". Empty name = the property
    // value already carries its own (EMUI). Unknown vendor / no property → just the Android version.
    val roms = listOf(
        "ColorOS" to "ro.build.version.oplusrom",
        "ColorOS" to "ro.build.version.opporom",
        "MIUI" to "ro.miui.ui.version.name",
        "OriginOS" to "ro.vivo.os.version",
        "" to "ro.build.version.emui",
        "" to "ro.rom.version",
    )
    val rom = runCatching {
        val sp = Class.forName("android.os.SystemProperties")
        val get = sp.getMethod("get", String::class.java)
        var found: String? = null
        for ((name, prop) in roms) {
            val v = (get.invoke(null, prop) as? String).orEmpty().trim()
            if (v.isNotBlank()) { found = if (name.isBlank()) v else "$name $v"; break }
        }
        found
    }.getOrNull()
    return if (!rom.isNullOrBlank()) "$android · $rom" else android
}

// Whether this app is the default SMS app. RoleManager on 29+: the legacy
// Telephony.Sms.getDefaultSmsPackage() can lag or disagree with the role (seen on an emulator where
// the role was held but the legacy setting was still null), and it is the ROLE that actually gates
// writing to / deleting from the SMS provider. Same rule deviceCaps() uses.
fun isDefaultSmsApp(ctx: Context): Boolean = runCatching {
    val app = ctx.applicationContext
    if (Build.VERSION.SDK_INT >= 29)
        app.getSystemService(android.app.role.RoleManager::class.java)
            ?.isRoleHeld(android.app.role.RoleManager.ROLE_SMS) == true
    else android.provider.Telephony.Sms.getDefaultSmsPackage(app) == app.packageName
}.getOrDefault(false)

// What this phone can actually still do, reported with the SIM list so the web can say so.
// Without it a lost permission is invisible from the browser: notification access can be revoked
// by a ROM update or "clear data", and missed-call capture then stops silently while SMS keeps
// working (that path is a broadcast, not a notification). Booleans only — no PII — but it rides
// inside the same encrypted blob anyway.
fun deviceCaps(ctx: Context): Map<String, Boolean> {
    val app = ctx.applicationContext
    val notif = runCatching {
        val flat = android.provider.Settings.Secure.getString(
            app.contentResolver, "enabled_notification_listeners"
        ).orEmpty()
        flat.split(":").any {
            android.content.ComponentName.unflattenFromString(it)?.packageName == app.packageName
        }
    }.getOrDefault(false)

    val sms = runCatching {
        if (Build.VERSION.SDK_INT >= 29)
            app.getSystemService(android.app.role.RoleManager::class.java)
                ?.isRoleHeld(android.app.role.RoleManager.ROLE_SMS) == true
        else android.provider.Telephony.Sms.getDefaultSmsPackage(app) == app.packageName
    }.getOrDefault(false)

    val send = runCatching {
        app.checkSelfPermission(android.Manifest.permission.SEND_SMS) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
    }.getOrDefault(false)

    // Whether the SMS broadcast path is armed. Together with notif (the listener path) and sms
    // (the default-app path) this is what the web needs to say "can this phone still capture an
    // SMS at all" — a question independent of whether its poll is currently alive, since an
    // incoming SMS wakes even a frozen app.
    val recv = runCatching {
        app.checkSelfPermission(android.Manifest.permission.RECEIVE_SMS) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
    }.getOrDefault(false)

    val battery = runCatching {
        app.getSystemService(android.os.PowerManager::class.java)
            ?.isIgnoringBatteryOptimizations(app.packageName) == true
    }.getOrDefault(true)

    return mapOf(
        "notif" to notif, "sms" to sms, "send" to send, "batt" to battery, "recv" to recv,
    )
}

// --- did this phone actually stay alive? ------------------------------------------------------
// No API reports whether an OEM's private autostart list is set — Huawei's 应用启动管理, Xiaomi's
// 自启动 and the rest are unreadable — so asking "is it configured?" cannot be answered honestly.
// What CAN be answered is the question that actually matters: did the phone keep running? Every
// poll stamps the clock; a gap far larger than the polling interval means we were frozen or
// killed in between. That is evidence rather than a guess, and it is the only way to tell a
// correctly configured phone from one the ROM is quietly suspending.
private const val KEY_WALL = "lastWall"
private const val KEY_UP = "lastUp"
private const val KEY_GAPS = "gaps"
private const val KEY_WORST = "worstGap"
private const val GAP_WINDOW_MS = 24 * 60 * 60 * 1000L

fun noteAlive(ctx: Context, expectedMs: Long) {
    val p = ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val nowWall = System.currentTimeMillis()
    val nowUp = android.os.SystemClock.elapsedRealtime()
    val lastWall = p.getLong(KEY_WALL, 0L)
    val lastUp = p.getLong(KEY_UP, 0L)

    if (lastWall > 0L) {
        val gap = nowWall - lastWall
        // elapsedRealtime counts sleep but resets on boot, so it going backwards means the phone
        // restarted — legitimate downtime, not a kill, and it must not be blamed on the ROM.
        val rebooted = nowUp < lastUp
        // Longest gap, whatever its size: a phone frozen for a few minutes at a time never trips
        // the threshold below, so the count stays at zero while messages are in fact delayed.
        // Rolling over 24h, not since-install — an all-time maximum never recovers, so a phone
        // that has since been fixed keeps displaying its worst-ever number for good, which reads
        // as "still broken" and makes the metric useless for checking whether a fix worked.
        if (!rebooted) {
            // Type-safe: an older build stored this key as a Long, and SharedPreferences throws
            // ClassCastException on a mismatched read. Unhandled that would abort the poll, not
            // just the metric. Treating a legacy value as absent also resets it, which is what
            // it deserves — the old number was an all-time maximum with no way to recover.
            val rec = readWorst(p).split("/")
            val prevGap = rec.getOrNull(0)?.toLongOrNull() ?: 0L
            val prevAt = rec.getOrNull(1)?.toLongOrNull() ?: 0L
            val expired = nowWall - prevAt > GAP_WINDOW_MS
            if (expired || gap > prevGap) p.edit().putString(KEY_WORST, "$gap/$nowWall").apply()
        }
        // x3, not x2: at a 5-minute asleep interval, x2 fires on a single missed poll — which an
        // alarm being coalesced explains just as well as a freeze — and calling that "killed" in
        // red made a healthy phone look broken. Two consecutive misses is a real signal; the raw
        // maximum above still exposes anything smaller for anyone comparing two phones.
        if (!rebooted && gap > expectedMs * 3) {
            val kept = p.getString(KEY_GAPS, "").orEmpty()
                .split(",").filter { it.isNotBlank() }
                .filter { (it.substringBefore('/').toLongOrNull() ?: 0L) > nowWall - GAP_WINDOW_MS }
                .takeLast(19)
            val next = (kept + "$nowWall/${gap / 60000}").joinToString(",")
            p.edit().putString(KEY_GAPS, next).apply()
        }
    }
    p.edit().putLong(KEY_WALL, nowWall).putLong(KEY_UP, nowUp).apply()
}

// --- did this phone have network when it woke? ------------------------------------------------
// The gap data above answers "did the alarm keep firing"; it cannot answer "and when it fired,
// could it reach the internet". On Huawei those are different failures: 休眠时保持网络连接, left
// off, drops Wi-Fi/data shortly after screen-off and restores it on screen-on — so the phone
// wakes exactly on schedule (small gaps, looks healthy) yet forwards nothing until it is picked
// up. Without adb on that handset this counter is the only way to tell the two apart from the web.
// Only screen-off wakes count: a no-network reading while the screen is on says nothing about the
// sleep gate.
private const val KEY_NW = "netWakes"
private const val KEY_NN = "netNoNet"
private const val KEY_NWIN = "netWinStart"

fun noteNetwork(ctx: Context, screenOff: Boolean, hasNet: Boolean) {
    if (!screenOff) return
    val p = ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val now = System.currentTimeMillis()
    var start = p.getLong(KEY_NWIN, 0L)
    var wakes = p.getInt(KEY_NW, 0)
    var noNet = p.getInt(KEY_NN, 0)
    // ponytail: 24h tumbling window, not sliding — a coarse diagnostic counter; resetHealth() and
    // 「重新测量」 both clear it, and an exact sliding window isn't worth the per-wake bookkeeping.
    if (start == 0L || now - start > GAP_WINDOW_MS) { start = now; wakes = 0; noNet = 0 }
    wakes++
    if (!hasNet) noNet++
    p.edit().putLong(KEY_NWIN, start).putInt(KEY_NW, wakes).putInt(KEY_NN, noNet).apply()
}

// (screen-off wakes in the window, how many of them found no network)
fun netWakes(ctx: Context): Pair<Int, Int> {
    val p = ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val start = p.getLong(KEY_NWIN, 0L)
    if (start == 0L || System.currentTimeMillis() - start > GAP_WINDOW_MS) return 0 to 0
    return p.getInt(KEY_NW, 0) to p.getInt(KEY_NN, 0)
}

// activeNetwork with an INTERNET-capable transport. NOT gated on NET_CAPABILITY_VALIDATED: the
// validation probe can lag a genuinely-working link and would report a false "no network", and a
// false alarm is exactly what makes this metric untrustworthy. When an OEM cuts the radio on
// sleep, activeNetwork drops to null, which this catches without the probe.
fun hasInternet(ctx: Context): Boolean = runCatching {
    val cm = ctx.applicationContext
        .getSystemService(android.net.ConnectivityManager::class.java) ?: return false
    val n = cm.activeNetwork ?: return false
    cm.getNetworkCapabilities(n)
        ?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
}.getOrDefault(false)

// Which pipe the phone is on right now: "wifi", "cell" (mobile data — burns the SIM's data
// allowance), or "" (offline/unknown). Purely informational; surfaced on the web card so a phone
// silently running on cellular instead of Wi-Fi is visible at a glance.
fun currentTransport(ctx: Context): String = runCatching {
    val cm = ctx.applicationContext
        .getSystemService(android.net.ConnectivityManager::class.java) ?: return ""
    val caps = cm.getNetworkCapabilities(cm.activeNetwork ?: return "") ?: return ""
    when {
        caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
        caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> cellGen(ctx)
        else -> ""
    }
}.getOrDefault("")

// "5G"/"4G"/"3G"/"2G" for the mobile data connection, "蜂窝" when the generation can't be read
// (needs READ_PHONE_STATE — a receive-only phone may not have it). dataNetworkType is what the
// status bar shows; 5G NSA can still report LTE here, which is a known platform limitation we
// accept rather than wire up a TelephonyDisplayInfo listener for a corner watermark.
// ponytail: dataNetworkType only; TelephonyDisplayInfo if true-5G-NSA detection ever matters.
private fun cellGen(ctx: Context): String = runCatching {
    val tm = ctx.applicationContext
        .getSystemService(android.telephony.TelephonyManager::class.java) ?: return "蜂窝"
    val t = if (Build.VERSION.SDK_INT >= 30) tm.dataNetworkType else @Suppress("DEPRECATION") tm.networkType
    when (t) {
        android.telephony.TelephonyManager.NETWORK_TYPE_NR -> "5G"
        android.telephony.TelephonyManager.NETWORK_TYPE_LTE -> "4G"
        android.telephony.TelephonyManager.NETWORK_TYPE_UMTS,
        android.telephony.TelephonyManager.NETWORK_TYPE_HSDPA,
        android.telephony.TelephonyManager.NETWORK_TYPE_HSUPA,
        android.telephony.TelephonyManager.NETWORK_TYPE_HSPA,
        android.telephony.TelephonyManager.NETWORK_TYPE_HSPAP,
        android.telephony.TelephonyManager.NETWORK_TYPE_EVDO_0,
        android.telephony.TelephonyManager.NETWORK_TYPE_EVDO_A,
        android.telephony.TelephonyManager.NETWORK_TYPE_EVDO_B,
        android.telephony.TelephonyManager.NETWORK_TYPE_EHRPD,
        android.telephony.TelephonyManager.NETWORK_TYPE_TD_SCDMA -> "3G"
        android.telephony.TelephonyManager.NETWORK_TYPE_GPRS,
        android.telephony.TelephonyManager.NETWORK_TYPE_EDGE,
        android.telephony.TelephonyManager.NETWORK_TYPE_CDMA,
        android.telephony.TelephonyManager.NETWORK_TYPE_1xRTT,
        android.telephony.TelephonyManager.NETWORK_TYPE_IDEN,
        android.telephony.TelephonyManager.NETWORK_TYPE_GSM -> "2G"
        else -> "蜂窝"
    }
}.getOrDefault("蜂窝")

// (number of interruptions in the last 24h, longest of them in minutes)
fun aliveGaps(ctx: Context): Pair<Int, Int> {
    val p = ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val cutoff = System.currentTimeMillis() - GAP_WINDOW_MS
    val mins = p.getString(KEY_GAPS, "").orEmpty()
        .split(",").filter { it.isNotBlank() }
        .mapNotNull {
            val at = it.substringBefore('/').toLongOrNull() ?: return@mapNotNull null
            if (at <= cutoff) null else it.substringAfter('/').toIntOrNull()
        }
    return mins.size to (mins.maxOrNull() ?: 0)
}

// Longest interval between two successful polls since install, in minutes. On a healthy phone
// this settles at the polling interval itself; anything much larger is the ROM suspending us.
private fun readWorst(p: android.content.SharedPreferences): String =
    runCatching { p.getString(KEY_WORST, "").orEmpty() }.getOrDefault("")

// Wipes the liveness history so a phone can be measured again from scratch — after changing an
// OEM setting, the old numbers say nothing about whether the change worked.
fun resetHealth(ctx: Context) {
    ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
        .remove(KEY_GAPS).remove(KEY_WORST).remove(KEY_WALL).remove(KEY_UP)
        .remove(KEY_NW).remove(KEY_NN).remove(KEY_NWIN).apply()
}

fun worstGapMinutes(ctx: Context): Int {
    val p = ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val rec = readWorst(p).split("/")
    val gap = rec.getOrNull(0)?.toLongOrNull() ?: 0L
    val at = rec.getOrNull(1)?.toLongOrNull() ?: 0L
    if (at == 0L || System.currentTimeMillis() - at > GAP_WINDOW_MS) return 0   // aged out
    return (gap / 60000L).toInt()
}
