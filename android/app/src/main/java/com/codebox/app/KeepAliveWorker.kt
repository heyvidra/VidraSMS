package com.codebox.app

import android.content.Context
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

// A second, independent way back to life.
//
// The alarm chain in ForwardService is the fast path, but an aggressive OEM power manager can
// cancel an app's alarms and kill its service outright — measured: an OPPO stayed online with the
// screen off while a Huawei went silent within half an hour under identical settings. WorkManager
// keeps its own schedule in its own database and the platform re-registers it after a kill or a
// reboot, so whichever of the two the ROM spares is enough to bring the service back.
//
// 15 minutes is WorkManager's floor for periodic work, which is fine: this is a resurrector, not
// the poller. If the service is already up, starting it again is a no-op.
class KeepAliveWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
    override fun doWork(): Result {
        ForwardService.start(applicationContext)
        // Poll here too, so even a phone whose service cannot stay resident still checks in every
        // 15 minutes rather than looking permanently offline.
        runCatching { pollOutbox(applicationContext) }
        return Result.success()
    }

    companion object {
        private const val NAME = "keepalive"

        fun schedule(ctx: Context) {
            if (!configured()) return
            // KEEP, not REPLACE: replacing on every app open would reset the 15-minute clock and
            // could starve it on a phone the user opens often.
            runCatching {
                WorkManager.getInstance(ctx.applicationContext).enqueueUniquePeriodicWork(
                    NAME,
                    ExistingPeriodicWorkPolicy.KEEP,
                    PeriodicWorkRequestBuilder<KeepAliveWorker>(15, TimeUnit.MINUTES).build(),
                )
            }
        }
    }
}
