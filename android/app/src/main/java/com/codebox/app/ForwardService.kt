package com.codebox.app

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import java.util.concurrent.Executors

// The always-on host. A foreground service is the one thing Android won't quietly kill under
// Doze or an OEM battery saver, so the outbox poller + heartbeat live here — moved off the
// notification listener, which the system can reclaim under memory pressure. It is resurrected
// four ways: START_STICKY relaunch, BOOT_COMPLETED, app open (MainActivity), and a listener rebind.
// ponytail: the price of a foreground service is one permanent low-priority notification —
// unavoidable, the platform requires it.
//
// Polling is driven by AlarmManager, NOT by a ScheduledExecutorService. A foreground service
// keeps the *process* alive but does nothing to keep the *CPU* awake: once a real phone suspends
// after screen-off, an executor's timer simply stops advancing and the phone goes silent until
// the screen comes back on — which is exactly what "锁屏后就离线" was. Only an RTC_WAKEUP alarm
// wakes the device. (An emulator never reproduces this: it doesn't truly suspend.)
class ForwardService : Service() {

    private val io = Executors.newSingleThreadExecutor()
    private var armed = false

    override fun onBind(intent: Intent?): IBinder? = null

    // Fired by the alarm, and by the screen coming on. Polls on a worker thread under a wake
    // lock, then arms the next one — chaining rather than repeating, so a slow send can never
    // stack polls on top of each other.
    private val tick = object : BroadcastReceiver() {
        override fun onReceive(c: Context?, i: Intent?) = poll()
    }

    override fun onCreate() {
        super.onCreate()
        // SCREEN_ON matters because the asleep cadence is 5 minutes: without it, unlocking the
        // phone to send something from the web could still mean waiting out the rest of that
        // interval. Waking the screen polls at once and drops back to the 20s cadence. It can
        // only be registered at runtime — the manifest is ignored for this one.
        // Only SCREEN_ON is a broadcast now; the alarm tick goes straight to the service. Some
        // ROMs drop this one too (ColorOS does), which costs nothing — it is an optimisation that
        // polls immediately on unlock, never the thing the chain depends on.
        val f = IntentFilter(Intent.ACTION_SCREEN_ON)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(tick, f, Context.RECEIVER_EXPORTED)
        else registerReceiver(tick, f)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Must reach the foreground within 5s of startForegroundService or the system crashes us.
        val note = buildNote()
        if (Build.VERSION.SDK_INT >= 34)
            startForeground(NOTE_ID, note, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else
            startForeground(NOTE_ID, note)

        if (intent?.action == ACTION_POLL) {
            poll()                                   // an alarm tick
        } else if (!armed) {
            armed = true; poll()                     // first start, or a START_STICKY revival
        }
        // Otherwise it is a redundant start (app resume, listener rebind) and the chain is
        // already running — starting another would stack polls on top of each other.
        return START_STICKY   // relaunched (with a null intent) if the OS ever reclaims us
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(tick) }
        getSystemService(AlarmManager::class.java)?.cancel(alarmIntent())
        armed = false
    }

    private fun poll() {
        // Arm the next alarm BEFORE the work, not only after it. Between here and the finally
        // there was no pending alarm at all, so a poll that outlived its wake lock (a stuck send
        // waits 60s per message) could leave the device asleep with nothing scheduled to wake it
        // — polling and the heartbeat then stopped until something unrelated woke the phone.
        // FLAG_UPDATE_CURRENT means the finally's schedule() simply replaces this watchdog.
        schedule(WATCHDOG_MS)
        io.execute {
            // The alarm wakes the CPU, but only briefly — without this the device can suspend
            // again mid-request and the poll dies half-finished.
            val wl = getSystemService(PowerManager::class.java)
                ?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "codebox:poll")
            runCatching { wl?.acquire(90_000L) }
            try {
                // Stamp before the work: what matters is when we last managed to run at all.
                // Always judged against the ASLEEP interval, never the current one: the screen
                // state now says nothing about the regime the gap actually spanned, and using the
                // 20s awake figure made a perfectly ordinary one-minute gap count as "suspended".
                // A yardstick that cries wolf is worse than none, so use the lenient one always.
                runCatching { noteAlive(applicationContext, ASLEEP_MS) }
                // Same wake that would carry an inbound upload, so its network state is a faithful
                // sample of whether an SMS arriving now could be forwarded. Screen-off only —
                // that is the regime where an OEM sleep gate would have cut the radio.
                val screenOff = getSystemService(PowerManager::class.java)?.isInteractive == false
                runCatching {
                    noteNetwork(applicationContext, screenOff, hasInternet(applicationContext))
                }
                runCatching { pollOutbox(applicationContext) }
                runCatching { Updater.maybeCheck(applicationContext) }
            } finally {
                runCatching { if (wl?.isHeld == true) wl.release() }
                schedule()
            }
        }
    }

    private fun schedule(overrideMs: Long? = null) {
        val am = getSystemService(AlarmManager::class.java) ?: return
        // Screen off means nobody is waiting on a web-sent SMS this second, and each wake costs a
        // CPU wake plus an HTTPS round trip with the radio's tail on top — at once a minute that
        // is ~1400 wakes a day and a real dent in the battery. Received SMS don't depend on this
        // at all (they arrive by broadcast, instantly either way); the only things that get
        // slower while the phone sleeps are web-initiated sends and the online indicator.
        val interactive = getSystemService(PowerManager::class.java)?.isInteractive ?: true
        val at = System.currentTimeMillis() +
            (overrideMs ?: if (interactive) AWAKE_MS else ASLEEP_MS)
        // ...AllowWhileIdle fires even inside Doze; its ~9 minute throttle applies only to apps
        // that are not battery-optimisation exempt, which is the exemption MainActivity nags for.
        // Exact, because the inexact variant is handed a 45s window — measured — which would turn
        // a web-triggered send into a minute-long wait. Where the platform won't allow exact
        // alarms without the user granting it (33+), the looser one still works, just later.
        val exact = Build.VERSION.SDK_INT < 31 || am.canScheduleExactAlarms()
        runCatching {
            if (exact) am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, alarmIntent())
            else am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, alarmIntent())
        }.onFailure {   // SecurityException if the permission is revoked between check and call
            runCatching { am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, alarmIntent()) }
        }
    }

    // Delivered straight to the service, NOT as a broadcast. ColorOS says so in its own log —
    // "OppoBroadcastManager: skip broadcast for pkg:com.codebox.app" — and a dropped tick means
    // poll() never runs, so the chain never re-arms and polling stops entirely. Measured on an
    // OPPO R11: /api/outbox was not called for hours while the 15-minute WorkManager backstop
    // was the only thing still checking in. A service PendingIntent is not subject to that
    // filter, and starting an already-foreground service from an alarm is allowed.
    private fun alarmIntent(): PendingIntent {
        val i = Intent(this, ForwardService::class.java).setAction(ACTION_POLL)
        return if (Build.VERSION.SDK_INT >= 26)
            PendingIntent.getForegroundService(this, 0, i, PI_FLAGS)
        else
            PendingIntent.getService(this, 0, i, PI_FLAGS)
    }

    private fun buildNote(): Notification {
        // IMPORTANCE_MIN: silent, collapsed to a single line at the bottom of the shade.
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(
            NotificationChannel(CHANNEL, "同步服务", NotificationManager.IMPORTANCE_MIN)
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("验证码同步")
            .setContentText("正在后台运行")
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val CHANNEL = "forward"
        private const val NOTE_ID = 7
        private const val ACTION_POLL = "com.codebox.app.POLL"
        private const val PI_FLAGS = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        private const val AWAKE_MS = 20_000L
        private const val ASLEEP_MS = 5 * 60_000L   // battery over send latency while asleep
        // Longer than any poll can legitimately take, so it only ever fires if one got stuck.
        private const val WATCHDOG_MS = 10 * 60_000L

        // Best-effort. Foreground (MainActivity) and BOOT_COMPLETED are exempt from the Android
        // 12+ background-FGS-start ban; a listener-rebind start may be denied → runCatching eats it.
        fun start(ctx: Context) {
            if (!configured()) return
            runCatching { ctx.startForegroundService(Intent(ctx, ForwardService::class.java)) }
        }

        // Poll right now instead of waiting for the next alarm. Used when something the server
        // ought to know about just changed — the default-SMS role being granted, say — so the
        // web stops showing a capability snapshot that is minutes out of date.
        fun pollNow(ctx: Context) {
            if (!configured()) return
            runCatching {
                ctx.startForegroundService(
                    Intent(ctx, ForwardService::class.java).setAction(ACTION_POLL)
                )
            }
        }
    }
}
