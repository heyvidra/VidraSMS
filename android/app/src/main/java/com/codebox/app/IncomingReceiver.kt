package com.codebox.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log

// The "cheap B" path: fires only when the (hard-restricted) SMS permission is actually held —
// which happens on an adb install or if the app is made the default SMS app, but NOT on a plain
// sideload. When it does fire it funnels into the same forwardNow as the notification listener,
// and CodeStore dedups so nothing is forwarded twice.
class IncomingReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        // SMS_RECEIVED reaches any RECEIVE_SMS holder; SMS_DELIVER reaches only the default SMS
        // app. getMessagesFromIntent parses both, and forwardNow dedups if both fire.
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION &&
            intent.action != Telephony.Sms.Intents.SMS_DELIVER_ACTION) return

        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent)?.filterNotNull().orEmpty()
        if (parts.isEmpty()) return

        val sender = parts[0].displayOriginatingAddress ?: "未知"
        val body = parts.joinToString("") { it.displayMessageBody ?: "" }
        val ts = parts[0].timestampMillis

        // Which SIM received it. The extra key differs across versions, so try both; -1 → untagged.
        val subId = intent.getIntExtra("subscription",
            intent.getIntExtra("android.telephony.extra.SUBSCRIPTION_INDEX", -1))

        // enqueue commits on a background thread; goAsync holds the process at receiver priority
        // until forwardNow has stored and enqueued, so a fast process death can't lose the SMS.
        // simLabelForSub hits telephony (a slow binder call) — it MUST stay off the main thread,
        // or onReceive blocks long enough to ANR and the broadcast gets re-delivered as a dup.
        // Only the default SMS app receives SMS_DELIVER, and only it may write to the SMS
        // database — so that broadcast is exactly when we owe the phone a stored message and a
        // notification. SMS_RECEIVED reaches us in other configurations, where the real default
        // app is already doing both and duplicating them would be wrong.
        val isDeliver = intent.action == Telephony.Sms.Intents.SMS_DELIVER_ACTION

        val pending = goAsync()
        val app = context.applicationContext
        Thread {
            try {
                // Local first, network second. The upload used to sit between the message
                // arriving and it appearing in the stock Messages app, so on a slow or blocked
                // network the phone's own SMS list lagged by tens of seconds — on a handset that
                // is also an ordinary phone, that is the part the user notices.
                val fresh = recordIncoming(app, sender, body, ts)
                if (fresh && isDeliver) {
                    runCatching { storeInbox(app, sender, body, ts, subId) }
                    runCatching { notifySms(app, sender, body, ts) }
                }
                // Anything thrown past here would reach a bare Thread with no handler and take
                // the whole process down — including the foreground service that keeps
                // forwarding alive — so nothing is allowed to escape.
                if (fresh) runCatching { deliver(app, sender, body, ts, simLabelForSub(app, subId)) }
            } catch (e: Throwable) {
                Log.e(TAG, "incoming SMS handling failed", e)
            } finally { pending.finish() }
        }.start()
    }
}
