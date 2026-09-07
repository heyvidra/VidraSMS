package com.codebox.app

import android.app.Notification
import android.provider.Telephony
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import java.util.concurrent.Executors

// Reads incoming-SMS notifications instead of the SMS itself. "Notification access" is a
// special access the user grants in Settings — unlike RECEIVE_SMS/READ_SMS it is NOT a
// hard-restricted permission, so it works on a sideloaded install. Only notifications from
// the phone's default SMS app are looked at, so other apps' notifications are ignored.
class CodeListener : NotificationListenerService() {

    private val io = Executors.newSingleThreadExecutor()

    // The outbox poller + heartbeat now live in ForwardService (a foreground service the OS
    // won't quietly kill). A listener rebind is a reliable moment to make sure it's up.
    override fun onListenerConnected() {
        ForwardService.start(this)
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        // Our own notifications, first of all: once this app IS the default SMS app the package
        // check below matches itself, and the keep-alive service's ongoing notification would be
        // forwarded as if it were an SMS. Nothing is lost by skipping us — when we hold the role
        // the real messages arrive through SMS_DELIVER (IncomingReceiver), not through here.
        if (sbn.packageName == packageName) return

        val n = sbn.notification ?: return
        // Skip the "N new messages" bundle summary — its per-message children carry the text.
        if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return

        val ex = n.extras
        val title = ex.getCharSequence(Notification.EXTRA_TITLE)?.toString()?.trim().orEmpty()
        val text = (ex.getCharSequence(Notification.EXTRA_TEXT)
            ?: ex.getCharSequence(Notification.EXTRA_BIG_TEXT))?.toString()?.trim().orEmpty()
        val ts = if (sbn.postTime > 0) sbn.postTime else System.currentTimeMillis()

        val smsPkg = runCatching { Telephony.Sms.getDefaultSmsPackage(this) }.getOrNull()
        val dialerPkg = runCatching {
            getSystemService(android.telecom.TelecomManager::class.java)?.defaultDialerPackage
        }.getOrNull()

        // What counts as "an SMS app" is asked of the platform rather than assumed: every package
        // declaring an SMS_DELIVER receiver is one, by Android's own definition. Matching only the
        // CURRENT default was the bug. getDefaultSmsPackage() is the legacy setting, and this ROM is
        // already known to leave it disagreeing with RoleManager (see isDefaultSmsApp) — so when we
        // lose the role while the stale setting still names us, the stock messaging app's
        // notifications match nothing and every SMS is dropped: visible in the shade, never
        // forwarded, with no permission looking wrong. Union, not replacement: the old check still
        // holds wherever it worked.
        val smsApps = smsCapablePackages(this)

        when {
            sbn.packageName == smsPkg || sbn.packageName in smsApps -> {
                if (text.isEmpty()) { noteNotif(this, sbn.packageName, "丢弃·通知无正文"); return }
                // When we hold RECEIVE_SMS the broadcast path (IncomingReceiver) captures every SMS
                // — with its exact body AND the SIM it arrived on, which this notification (posted
                // by another app) does not know. Forwarding from here too meant the two paths raced
                // the dedup: whichever won decided the message, so the SAME SIM showed a SIM label
                // on some messages and a bare device name on others. Defer to the broadcast path;
                // only forward from here when we cannot receive the broadcast at all (a pure
                // sideload with no RECEIVE_SMS), where this notification is the one and only capture.
                if (hasReceiveSms()) { noteNotif(this, sbn.packageName, "跳过·走广播路径"); return }
                noteNotif(this, sbn.packageName, "已转发")
                io.execute {
                    forwardNow(applicationContext, title.ifEmpty { "未知" }, stripUnreadPrefix(text), ts)
                }
            }
            // A missed call is the only phone event worth a message: on a dedicated forwarding
            // phone nobody answers, so this fires once per missed call. Ringing / in-progress
            // notifications are deliberately ignored — they would double up. Read from the
            // notification rather than the call log — but NOT because the call log is out of
            // reach. That earlier claim was wrong: checked against the device's own roles.xml
            // (pulled from GooglePermissionController.apk on an Android 11 image), ROLE_SMS grants
            // permission-set "phone", and that set contains READ_CALL_LOG. The real reason is
            // simply that we do not declare READ_CALL_LOG today, so there is nothing to read.
            dialerPkg != null && sbn.packageName == dialerPkg -> {
                if (!isMissedCall(n)) return
                noteNotif(this, sbn.packageName, "已转发·未接来电")
                io.execute {
                    val app = applicationContext
                    forwardNow(app, callerOf(title, text), "未接来电", ts, soleSimLabel(app))
                }
            }
            // The case that had no evidence at all: a notification we decided was not ours to
            // read. Recording it is the whole point — "看得到通知但没转发" is indistinguishable
            // from "没收到通知" until the phone can say which package it just ignored.
            else -> noteNotif(this, sbn.packageName, "忽略·不在短信/拨号应用列表")
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) { /* nothing to do */ }

    // True when the SMS broadcast path is armed, so it — not this notification — is the authoritative
    // capture. Held on an adb install or when this app is the default SMS app; absent on a plain
    // browser sideload, which is exactly when the notification path must still forward.
    private fun hasReceiveSms(): Boolean =
        checkSelfPermission(android.Manifest.permission.RECEIVE_SMS) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
}

// AOSP's Telecom and Dialer never call setCategory(), so category is null on most phones —
// filtering on CATEGORY_MISSED_CALL alone would silently drop nearly every missed call. The
// channel id is the dependable signal ("phone_missed_call" on Google Dialer, "TelecomMissedCalls"
// on AOSP); category is kept only as a fast path for the dialers that do set it.
fun isMissedCall(n: Notification): Boolean =
    n.category == Notification.CATEGORY_MISSED_CALL ||
        n.channelId?.contains("missed", ignoreCase = true) == true

// Dialers disagree on which field holds the caller: AOSP/Google put the number (or the contact
// name, when it resolves) in the text with a localized "Missed call" label in the title; several
// OEM dialers invert that. So prefer whichever field actually looks like a number, and only fall
// back to "the field that isn't the label" — that fallback is locale-bound, the number test isn't.
// Dialer wraps values in BidiFormatter, so the invisible LRM/RLM marks must come off first.
private val MISSED_LABEL = Regex("未接|missed", RegexOption.IGNORE_CASE)
private val DIALABLE = Regex("^[+0-9][0-9 ()-]{2,}$")

// Removes a leading unread/count marker a messaging app prepends to its notification when several
// messages are pending — "[2 unread] ", "[2条未读]", "[3 new] " — so a notification-captured SMS
// matches the undecorated body the broadcast path forwards and the two collapse in dedup. Requires
// a digit inside the bracket, so a genuine "[验证码]"-style body is left untouched.
private val UNREAD_PREFIX =
    Regex("""^\s*\[\s*\d+\s*(unread|未读|条未读|条新信息|新信息|new)?\s*]\s*""", RegexOption.IGNORE_CASE)

fun stripUnreadPrefix(s: String): String = UNREAD_PREFIX.replace(s, "")

fun callerOf(title: String, text: String): String {
    val fields = listOf(title, text)
        .map { it.replace("‎", "").replace("‏", "").trim() }
        .filter { it.isNotEmpty() }
    return fields.firstOrNull { DIALABLE.matches(it) }
        ?: fields.firstOrNull { !MISSED_LABEL.containsMatchIn(it) }
        ?: "未知号码"
}


// Every package the system itself treats as an SMS app: those declaring an SMS_DELIVER receiver.
// Derived from the device, so no OEM package name is ever hardcoded or guessed. Needs the
// <queries> entry in the manifest — without it Android 11+ package visibility filters this to
// nothing and the set comes back empty.
internal fun smsCapablePackages(ctx: android.content.Context): Set<String> = runCatching {
    ctx.packageManager
        .queryBroadcastReceivers(android.content.Intent(Telephony.Sms.Intents.SMS_DELIVER_ACTION), 0)
        .mapNotNull { it.activityInfo?.packageName }
        .filter { it != ctx.packageName }
        .toSet()
}.getOrDefault(emptySet())

// The last notification this listener made a decision about, and what it decided. Rides up in the
// encrypted devinfo blob so a phone nobody can physically reach can still say why a message that
// plainly arrived was not forwarded. Package name only — never a title, never a body.
// ponytail: one prefs write per notification; this is a dedicated forwarding phone, the volume is
// a handful a day. Revisit only if it ever runs on a phone with real notification traffic.
private fun noteNotif(ctx: android.content.Context, pkg: String, verdict: String) {
    ctx.applicationContext.getSharedPreferences("dev", android.content.Context.MODE_PRIVATE)
        .edit().putString("lastNotif", "$pkg $verdict").apply()
}
