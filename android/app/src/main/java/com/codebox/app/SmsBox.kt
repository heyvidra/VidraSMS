package com.codebox.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log

// Keeping the phone usable as a normal phone.
//
// Since Android 4.4 the platform no longer writes incoming SMS into the system database — the
// default SMS app has to, and nobody else is allowed to. Once this app takes that role the stock
// Messages app therefore shows nothing new and posts no notifications: verified on an emulator,
// where five messages received while this app held the role were absent from content://sms.
// So we do both jobs the role comes with: store the message, and tell the user it arrived.

private const val SMS_CHANNEL = "sms"

// Whether to ALSO mirror messages into the system SMS database (the "dual-purpose phone" mode).
// OFF by default now. Mirroring gave the stock Messages app something to show, so the user opened
// it — and a stock SMS app that is no longer the default prompts to reclaim the role on every
// launch. That prompt is the "老弹默认短信", and confirming it is how the default kept flipping
// back to the stock app on ColorOS ("老掉默认"). With mirroring off the stock app has nothing
// new, nobody opens it, and the default stays put. Re-enable in 保活检查 if the phone must also
// read as a normal phone.
private const val PREF_MIRROR = "mirrorSms"
fun mirrorSms(ctx: Context): Boolean =
    ctx.applicationContext.getSharedPreferences("dev", Context.MODE_PRIVATE).getBoolean(PREF_MIRROR, false)
fun setMirrorSms(ctx: Context, on: Boolean) =
    ctx.applicationContext.getSharedPreferences("dev", Context.MODE_PRIVATE).edit().putBoolean(PREF_MIRROR, on).apply()

// Writes a received message where every SMS reader on the phone expects to find it. Only the
// default SMS app may insert here; otherwise the provider throws and we simply skip it.
fun storeInbox(ctx: Context, sender: String, body: String, ts: Long, subId: Int) {
    if (!mirrorSms(ctx)) return
    try {
        val v = ContentValues().apply {
            put(Telephony.Sms.ADDRESS, sender)
            put(Telephony.Sms.BODY, body)
            put(Telephony.Sms.DATE, ts)
            put(Telephony.Sms.DATE_SENT, ts)
            put(Telephony.Sms.READ, 0)
            put(Telephony.Sms.SEEN, 0)
            if (subId >= 0) put(Telephony.Sms.SUBSCRIPTION_ID, subId)
        }
        ctx.contentResolver.insert(Telephony.Sms.Inbox.CONTENT_URI, v)
    } catch (e: Exception) {
        Log.w(TAG, "inbox write failed", e)   // not the default SMS app, or provider refused
    }
}

// Same for a message this phone sent, so it shows up in the conversation rather than vanishing.
fun storeSent(ctx: Context, to: String, body: String, subId: Int) {
    if (!mirrorSms(ctx)) return
    try {
        val v = ContentValues().apply {
            put(Telephony.Sms.ADDRESS, to)
            put(Telephony.Sms.BODY, body)
            put(Telephony.Sms.DATE, System.currentTimeMillis())
            put(Telephony.Sms.READ, 1)
            put(Telephony.Sms.SEEN, 1)
            if (subId >= 0) put(Telephony.Sms.SUBSCRIPTION_ID, subId)
        }
        ctx.contentResolver.insert(Telephony.Sms.Sent.CONTENT_URI, v)
    } catch (e: Exception) {
        Log.w(TAG, "sent write failed", e)
    }
}

// The stock app cannot notify for messages it never receives, so the notification is ours to post
// too. Tapping it opens OUR list — not sms:. That used to open the stock Messages app, which (no
// longer being default) prompts to reclaim the role every time; tapping our own notification was
// one of the ways the default kept flipping back. Messages live in this app now, so a tap belongs here.
fun notifySms(ctx: Context, sender: String, body: String, ts: Long) {
    val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
    nm.createNotificationChannel(
        NotificationChannel(SMS_CHANNEL, "短信", NotificationManager.IMPORTANCE_HIGH)
    )
    val open = android.app.PendingIntent.getActivity(
        ctx, 0,
        Intent(ctx, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
        android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT,
    )
    val n = Notification.Builder(ctx, SMS_CHANNEL)
        .setSmallIcon(android.R.drawable.stat_notify_chat)
        .setContentTitle(sender)
        .setContentText(body)
        .setStyle(Notification.BigTextStyle().bigText(body))
        .setWhen(ts)
        .setAutoCancel(true)
        .setContentIntent(open)
        .build()
    // Distinct id per message so a second one doesn't replace the first; the ongoing keep-alive
    // notification uses id 7, so stay clear of it.
    runCatching { nm.notify(100 + (ts % 10000).toInt(), n) }
}
